# CipherVault full status report — 2026-10-03

Covers the 1–3 Oct engagement: enforced MFA, custody, soak, explorer UX,
audit-export fix, and Path B hardening. All claims below are verified
against live state, CI, or committed evidence files cited inline.

## 1. Progress (what was accomplished)

### Merged PRs

| PR | Content | Merged |
|---|---|---|
| #21 | v1.0.28 production assurance results (docs) | 2026-10-02 |
| #22 | MFA rollout tooling, custody activation, soak plan, review brief, lock-wait stats | 2026-10-02 |
| #23 | ADR-012 steps 1–3: sync records + health pill + push timers, CVKB1 passphrase backup envelope + CLI (drilled byte-identical), account-held vault locator, unified dashboard Linked Vaults panel, decentralization direction doc | 2026-10-03 |
| #24 | Public-explorer recovery notice + signed-in session summary (UX gaps 1+2) | 2026-10-03 |
| #25 | Audit-export cursor paging (OOM fix) — **open, all 12 CI checks green** | pending owner merge |

Plus 9 docs-only commits to main (soak/MFA/hardening evidence, rollout prep,
outreach drafts, secrets-browser design). Main tip at report time: `90681ff`,
tree clean, main CI green.

### MFA rollout — COMPLETE for Alice

- `cvacct_c6da30342f8b9d0601c15c8fcb3edc43` enrolled via owner ceremony;
  offline readiness verified `enforced_ready`; post-ceremony GCS backup
  roundtrip-verified.
- Negative check 2026-10-03: **PASS** (denied-before-code, allowed-after,
  owner-reported; `report/MFA_NEGATIVE_CHECK_2026-10-03.md`). No seeds,
  codes, or keys ever entered chat.

### DON / fleet recovery — COMPLETE

- Operator network was down: fixed via compose remap + DNS records
  (op1/op2/op3) + static IPs (34.59.81.124, 104.197.199.26, 34.139.15.56).
- op2's 6,345 ms latency attributed to DNS retry arithmetic; healthy
  steady-state 36 ms verified.

### Isolated soak — COMPLETE, torn down

- Canary e2-micro + driver e2-standard-2 (project
  `gen-lang-client-0627244320`, now 0 instances, billing unlinked).
- Rate steps: 50/150/400 rps saturated; knee at 10–50 rps.
- OOM root-caused: unbounded `audit_export` killed the canary at 703 MB
  RSS (08:16:38Z). Exports excluded from the 4 h run; fix is PR #25.
- 4 h @ 10 rps: **143,605 / 143,605 OK, 0 failures**, p50 13 ms / p95 53 ms.
- Backup-overlap under load: 150 MB in 7.2 s, zero errors.
- Restore rehearsal: `verified_isolated_restore` (24,727 versions
  decrypted, 102 sessions revoked, production untouched).
- Disk pressure: 86% and 97% windows, 0 failures both; integrity `ok` after.
- Evidence: `report/SOAK_EVIDENCE_2026-10-03.md`, raw files in `C:\tmp\soak\`.

### Explorer UX — diagnosed, fixed, shipped (local)

- Root-caused the "Enrolled Device Key does nothing" bug: the card
  forwarded `.click()` to a hidden *disabled* button — a silent DOM no-op
  whenever no vault was linked. Fixed (direct login call surfacing the
  server's actionable errors); fix verified and live in local CLI 1.0.28.
- Full parity investigation (`report/EXPLORER_FEATURE_PARITY_2026-10-03.md`):
  the online/local split is by design (server bind-time mode, 403-gated
  private APIs, tested), not a bug. ADR-012 unified login while keeping
  vault keys local, so online vault views are cryptographically out of reach.
- Shipped gaps 1+2 (PR #24, merged): Recovery-tab local-only notice and a
  signed-in session summary (account, MFA state, linked-vault count,
  Manage-account entry). Verified in local `--serve` mode; online pending
  rollout.

### Recovery hardening (Path B) — LIVE

- Owner chose same-admin hardening over theater-custody. Recovery project
  `cv-recovery-108687509435` + EU bucket created: uniform access,
  public-access-prevention, versioning, 30-day retention **set and locked**
  (`isLocked: true`, owner-authorized), 7-day soft-delete.
- Prod SA has create-only + policy-read (no read/delete, verified by
  attempt: 403s); owner holds restore-read.
- First backup 2026-10-03: prod DB (4 accts, 2 TOTP creds), rehearsal
  `verified_isolated_restore` (2 seeds decrypted), age-encrypted to the
  owner's offline key, uploaded **as the SA** via raw API with
  server-side `ifGenerationMatch=0`, owner round-trip hash-verified.
- Daily 02:00 UTC upload cron installed on cv-web-ui (RPO 24 h).
- Honestly recorded as hardening: `custody_activated` stays `false`.
  Evidence: `report/PATH_B_HARDENING_EVIDENCE_2026-10-03.md`.
- Notable finding: `gcloud storage cp` cannot work create-only (it
  pre-reads); uploads use the raw JSON API. The stock custody script has
  the same wrinkle — recorded, not changed.

## 2. Current state (live inventory, verified 2026-10-03 ~16:45Z)

### Production (project `gen-lang-client-0022105784`)

| Host | Zone | Status | Serves |
|---|---|---|---|
| cv-operator-1 | us-central1-a | RUNNING | op1.cipherv.online |
| cv-operator-2 | us-central1-b | RUNNING | op2.cipherv.online |
| cv-operator-3 | us-east1-b | RUNNING | op3.cipherv.online |
| cv-web-ui | us-east1-b | RUNNING | vault.cipherv.online (dashboard 1.0.28 build, account API, Caddy edge) |

Live prod probes: `/api/context` reports `public_explorer`, build 1.0.28,
account proxy on, full MFA/TOTP/WebAuthn capability set.

### Recovery (project `cv-recovery-108687509435`, #491837281576)

Bucket `gs://cv-account-recovery-108687509435` (EU): locked 30-day
retention, versioned, first archive
`account-hardening/20261003T163300Z-first-a8f3c1/account-backup.tar.gz.age`
(15,858 bytes, generation 1791045384597486, sha256 `78cd6ccc...0285`).
Billing: `01F1BE-3588EA-938035`.

### Decommissioned

Soak project `gen-lang-client-0627244320`: 0 instances, billing unlinked.
No residue.

### Repository

- Main `90681ff`, clean, CI green. Open PRs: #25 (paging fix, 12/12 green,
  ready to merge), #1 (stale 2024 copilot WIP — recommend closing).
- Local CLI: 1.0.28 installed at `~/.cargo/bin` (includes device-card fix
  and explorer guidance). Old 1.0.24 backed up to `%TEMP%`.
- Edge images for `fe901c9` (includes PR #24): build SUCCESS, digests
  resolved and recorded in `report/WEB_ROLLOUT_EDGE_1.0.28_PREP.md`.
  They predate PR #25.

### Security posture snapshot

- Alice MFA enforced + negative-verified. TOTP seeds and KEKs live only
  on prod (Secret Manager + container mounts) and in the age-encrypted
  recovery archive decryptable solely by the owner's offline key.
- Recovery archive encryption: age v1.3.2, recipient
  `age14v9uzph70chnqw9v975dpeh9gamthcle88qp56jkmzxemlx39pas9essuh`
  (public half; secret on owner's USB/Desktop, never transmitted).
- Independent review: brief complete (`docs/INDEPENDENT_REVIEW_BRIEF.md`),
  both outreach emails drafted (`report/EXTERNAL_REVIEW_OUTREACH_DRAFT.md`),
  **not yet sent**. No independent findings exist yet — all assurance to
  date is internal + agent-verified.

## 3. How far everything is working (feature status)

| Area | Status | Evidence |
|---|---|---|
| Local vault CLI (init, seal/unseal, files, snapshots, diff, FastCDC, guardians) | Working | full Rust suites green (local-store 29, cli 214, crypto 38, agent 2) |
| Local dashboard (`ui --local`) | Working | owner-confirmed: all features visible and functional |
| Device-key sign-in | Fixed + working | silent-no-op bug fixed, verified live |
| Hosted account (signup, passkey/TOTP/WebAuthn, sessions, MFA policy, recovery codes) | Working | Alice live; account suite 163/163 |
| Online explorer (telemetry, checkpoints, account mgmt, Linked Vaults) | Working as designed | live probes + parity report |
| Online explorer guidance (recovery notice, session summary) | Merged, live locally; online pending rollout | PR #24, `--serve` verified |
| Audit export (small chains) | Working | pre-existing tests green |
| Audit export (large chains) | **Fixed in PR #25, unmerged** — prod still OOM-risky on huge tenants | soak OOM + PR #25 |
| Encrypted recovery backups (daily, RPO 24 h) | Live, first backup verified | hardening evidence |
| Restore-from-backup | Rehearsed isolated (keys on prod host); owner decrypt drill not yet run | rehearsal outputs |
| Independent custody (Path A) | Blocked — needs 2nd human | draft fail-closed, correct |
| External security review | Briefed + drafted, uncommissioned | brief + drafts committed |

## 4. Improvements and enhancements delivered

1. **MFA enforcement is real, not a flag:** per-account requirement,
   offline readiness checks, post-ceremony backup, and a passed negative
   check — password-only access provably fails.
2. **One entity to the user (ADR-012):** auto-push + backup-health pill,
   passphrase-wrapped key backup (CVKB1, drilled live), unified
   login/dashboard, account-held vault locator — while keeping the crypto
   split that protects users (no server-side unwrap, keys never leave the
   device).
3. **Explorer honesty:** silent dead-ends replaced with guidance (device
   login errors, recovery-tab notice, signed-in summary). What cannot work
   online now says why and where to go instead.
4. **Export that cannot OOM the fleet:** bounded pages + streaming
   verification + per-page fail-closed (PR #25), plus playbook updates.
   Same fix also bounds disaster-recovery verification memory.
5. **Recovery that exists:** from zero off-site copies to locked-retention
   EU bucket, least-privilege create-only uploads proven as the SA,
   verified rehearse-before-upload, and a daily timer — with every limit
   documented instead of oversold.
6. **Operability:** DCO-signed commits throughout, CI green on main across
   OS matrix + CSP + audits, release/edge image pipeline proven (digests
   in hand), rollout/rollback procedure rehearsed on paper with live
   rollback digests captured.

## 5. Things left to work on or test (ordered)

### P0 — production correctness (do first, in this order)

1. **Merge PR #25** (owner, 1 click — 12/12 green). Until merged, prod
   account service can still OOM on huge audit exports. Current prod
   tenants are small (3 MB DB), so risk is latent, not active.
2. **Web rollout** (owner go-ahead + fresh digests). Merge #25 first, wait
   for the edge build on new main, re-resolve `main-<sha>` digests, then
   run the prepared `promote-immutable-web.ps1` (dry-run, then `-Apply`;
   rollback digests staged). This puts explorer guidance (PR #24) AND the
   paging fix (PR #25) online in one move. Procedure + live inputs:
   `report/WEB_ROLLOUT_EDGE_1.0.28_PREP.md`.
3. **Post-rollout verification:** `/api/context` build check, Recovery-tab
   notice visible online, signed-in summary appears after hosted login,
   one paged export walk against prod (`?limit=2`).
4. **First cron run check** (tomorrow 02:00 UTC): new object under
   `account-hardening/` + `UPLOAD_OK` line in
   `/opt/ciphervault-ui/recovery-upload.log`.

### P1 — assurance and recovery confidence

5. **Alert destination** (owner names email/webhook) → wire stale/failure
   alerts for the daily backup. Until then, failures are log-only.
6. **Owner decrypt drill** (owner, ~30 min, then quarterly): exact steps
   in `report/PATH_B_HARDENING_EVIDENCE_2026-10-03.md`. Proves the archive
   is restorable with ONLY the offline key + Secret Manager KEK copies —
   the one link not yet demonstrated end-to-end by owner hands.
7. **Send review outreach** (owner, 2 emails): drafts ready in
   `report/EXTERNAL_REVIEW_OUTREACH_DRAFT.md`. No production system should
   claim "reviewed" until Track A/B report back; schedule retests after
   fixes.

### P2 — planned enhancements

8. **Hosted-secrets browser:** design drafted
   (`docs/HOSTED_SECRETS_BROWSER_DESIGN.md`, 4 open questions). Implement
   only after reviewers weigh in.
9. **Path A custody:** needs a second trusted human + 7 strings. The
   fail-closed draft and planner stand ready; revisit when staffed.
10. **Housekeeping:** close stale PR #1 (2024 copilot WIP); decide the
   fleet-stop root cause from 2026-10-02 02:03 PDT (still unknown —
   carries a recurrence risk); optional destructive 100%-disk test on a
   disposable canary.

### Test coverage map (what is / is not yet proven)

| Proven | Not yet proven |
|---|---|
| Rust suites all green (163 account incl. paging) | Scheduled cron's first run (lands tomorrow) |
| UI audit + Chromium CSP green | Post-rollout online behavior (needs rollout) |
| 4 h soak 143,605/143,605 + backup/disk windows | Owner decrypt drill (needs owner hands) |
| Isolated rehearsals (soak + prod backup) | Independent pen-test / crypto review |
| MFA negative check (owner PASS) | Retest-after-findings (no findings yet) |
| SA create-only upload + owner round-trip | 100% ENOSPC behavior (deliberately skipped) |

## 6. Production-readiness verdict

**Ready for day-to-day usage** (local vault workflows, hosted accounts with
enforced MFA, online monitoring, daily encrypted recovery) **with three
near-term must-dos:** merge + roll out PR #25 (items 1–3), confirm the
cron's first run (item 4), and run the owner decrypt drill (item 6).
**Full production confidence** additionally requires commissioned
independent reviews with clean retests (item 7) and a second custodian for
true independence (item 9). Nothing above is oversold: every limit is
stated where it lives, and `custody_activated` remains honestly `false`.
