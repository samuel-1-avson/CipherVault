# Isolated soak evidence (2026-10-02 → 2026-10-03)

Canary `cv-soak-canary` (e2-micro, 10.128.0.2) + driver `cv-soak-driver`
(e2-standard-2, 10.128.0.3), project `gen-lang-client-0627244320`,
zone `us-central1-a`. Build `3b95bf9` (`52eb51ef…`). Synthetic-only,
torn down after. Raw artifacts: `C:\tmp\soak\`
(`soak-4h-10rps.json`, `soak-4h.log`, `phases.log`, `phase-*.json`,
`resource.jsonl`, 5,567 samples @10 s).

## Rate steps (pre-soak)

Seeded 16 accounts / 200 secrets / 1,500 pregrow rows. Smoke 1,795/1,795,
verify2 1,746/1,746. 50/150/400 rps steps all saturated the e2-micro;
sustainable knee between 10–50 rps. 4 h soak run at 10 rps.

## OOM root cause (pre-soak, filed as follow-up)

08:16:38Z the canary OOM-killed at 703 MB RSS: `audit_export` is unbounded
(it materializes the full audit set). No service change was made; exports
were excluded from the 4 h run (`--skip-export`, `audit_export` requests: 0
in the final JSON). Canary restarted on the same DB, verified healthy
before the soak. Follow-up: page/stream `audit_export`; prod e2-micros carry
the same risk today.

## 4 h soak (08:26:52Z → 12:26:52Z, 10 rps, exports excluded)

- 143,605 sent / 143,605 OK / 0 failures / 0 rejected / 0 driver-dropped;
  all statuses 200; 797 relogins, 48 step-ups, 0 scope refreshes.
- Latency overall: p50 12.97 ms, p95 52.81 ms, p99 3,468 ms, max 11,264 ms
  @ 9.97 rps. p99/max spikes coincide with backup-overlap, disk-pressure
  windows, and WAL checkpointing — no request failed.
- Per-label: value_read 64,625 (p50 11.74 ms); materialize_5 35,900 (p50
  24.6 ms); manual_rotation 28,720 (p50 10.15 ms); metadata_list 14,360
  (p50 14.88 ms).

## Backup overlap + restore rehearsal (during soak)

- Live backup of the 150 MB DB under load: 7.2 s, soak clean throughout.
- `restore-rehearsal` on the backup copy: `verified_isolated_restore`
  (16 accounts / 200 secrets / 24,727 versions decrypted, 1 TOTP seed,
  102 copied sessions revoked, production untouched).

## Disk-pressure windows (during soak, ~40 min mark)

- 86% window (08:58–09:02Z): 0 failures.
- 97% window (09:03–09:07Z): 0 failures, 0 rejected; stderr showed only
  normal DB lock-wait warnings, no sqlite disk errors.
- After release: `PRAGMA integrity_check` ok, disk back to 21%.
- Note: `/api/sync/health` 404s on the canary (pre-PR#23 build) — expected,
  not a disk symptom. True 100% ENOSPC deliberately not tested (corruption
  risk); recommend a disposable-canary destructive test if needed.

## Canary resources (post-restart capture, 23:41Z → 15:16Z)

- RSS: min 3.5 MB / avg 109 MB / max 442 MB (OOM peak 703 MB was pre-restart,
  from dmesg, during the unbounded export).
- CPU avg 6.9%, max 99.9% (transient spikes).
- DB file 2.9 MB → 338 MB over the run; WAL max 35 MB; min mem avail 162 MB
  (never exhausted post-restart).

## Final DB state

Integrity `ok`; 16 accounts / 51,239 secret versions / 467,588 access events.

## Teardown

`gcloud compute instances delete cv-soak-canary cv-soak-driver
--delete-disks=all` completed; `instances list` returns 0 items. No prod
fleet host was touched at any point.
