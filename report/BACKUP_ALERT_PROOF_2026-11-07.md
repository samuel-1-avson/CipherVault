# Backup Alert Deployment Proof — 2026-11-07 (P4)

## Wiring inventory (verified in-repo)

| Piece | Status |
|---|---|
| `scripts/recovery/backup_alert.py` (stdlib-only: healthchecks ping, webhook, PagerDuty v2, sanitization) | present, 303 lines |
| `scripts/recovery/cron-backup-wrapper.sh` (start/success/failure alerts, `\| \| true` so alerting never breaks backups) | present, wired |
| `ciphervault-account-custody.service.example` → `OnFailure=ciphervault-account-custody-failure@%n.service` | present |
| `ciphervault-account-custody-failure@.service.example` (alert dispatch on unit failure) | present |
| Daily 02:00 UTC timer | present |

## Fix applied today: fail loudly with nowhere to send

`run_alert()` with zero destinations configured used to print `Notice:` and
exit 0 — a failure nobody can hear. It now writes a `WARNING` to stderr and
returns non-zero, so systemd/cron records the gap. Covered by two new tests:
`test_run_alert_failure_without_destinations_fails_loudly`,
`test_run_alert_success_without_destinations_warns`.

## Verification (real tool output, 2026-11-07)

- `python -m unittest discover -s tests/recovery`: **50 tests, OK (1 skipped)** —
  alert dispatch, custody, multicloud, MFA readiness.
- `python -m unittest tests.recovery.test_backup_alert`: **9 tests, OK** (7 existing + 2 new).
- Live dispatch drill (real `backup_alert.py` vs localhost stub, planted fake
  `cvst1.` / `Bearer` tokens in message + log tail): **P4 DRILL PASS** —
  webhook POST delivered, healthcheck success + `/fail` pings received,
  raw tokens absent from all payloads, `[REDACTED]` present.

## Remaining manual step (host operator, not code)

1. Create `/etc/ciphervault/alert.env` on the backup host with one or more of:
   `CIPHERVAULT_ALERT_HEALTHCHECK_URL`, `CIPHERVAULT_ALERT_WEBHOOK_URL`,
   `CIPHERVAULT_ALERT_PAGERDUTY_KEY` (referenced by the failure service via
   `EnvironmentFile=-/etc/ciphervault/alert.env`).
2. Trigger a test failure (e.g. expired GCS creds in staging) and confirm the
   page arrives within 5 minutes.
3. Keep 7 days of heartbeat evidence, then mark P4 fully closed.
