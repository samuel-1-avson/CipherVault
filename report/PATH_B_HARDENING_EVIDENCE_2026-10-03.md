# Path B same-admin hardening evidence (2026-10-03)

This is HARDENING, not independent custody. Same human
(`user:samuelavson360@gmail.com`) administers both sides by owner choice
(PATH B authorized 2026-10-03). `custody_activated` stays `false` until
Path A (distinct humans) is satisfied. The independence planner was
deliberately NOT used — it would, correctly, refuse this shape.

## Destination

- Project `cv-recovery-108687509435` (#491837281576), billing
  `01F1BE-3588EA-938035` (slot freed by unlinking the torn-down soak
  project `gen-lang-client-0627244320`, 0 instances).
- Bucket `gs://cv-account-recovery-108687509435`: EU multi-region, uniform
  access, public-access-prevention enforced, versioning on, 30-day
  retention SET BUT NOT LOCKED (lock is irreversible — awaiting separate
  owner authorization), 7-day soft-delete.
- IAM: `serviceAccount:cv-web-runtime@gen-lang-client-0022105784...`
  has ONLY `roles/storage.objectCreator` + project role
  `cvRecoveryPolicyReader` (buckets.get/getIamPolicy) — no read, no
  delete. Owner holds `roles/storage.objectViewer` + policy-reader for
  restores (plus project ownership).

## First backup (2026-10-03 ~16:33Z, prod cv-web-ui)

- `ciphervault-account backup` (binary 1.0.28 copied from the live
  container) of the running prod DB: 450,560 bytes, sha256
  `ac5ae8322471aa96e98ff3b2feed80c95c4e7aec59b2aeff78cb55c35137e19d`;
  4 accounts / 3 devices / 8 recovery codes / 2 TOTP credentials.
- `restore-rehearsal` with live keys (copied to 0400 staging, shredded
  after): `verified_isolated_restore`, 2 TOTP seeds decrypted, 1 copied
  session revoked, `production_modified: false`.
- Bundle tarred (USTAR, `accounts.sqlite3` + `backup-receipt.json`) and
  age-encrypted to owner recipient
  `age14v9uzph70chnqw9v975dpeh9gamthcle88qp56jkmzxemlx39pas9essuh`
  (public half only; secret never left owner hands).
- Archive sha256 `78cd6ccc421aab5f65532e95e968af04023579e55b659a389949cdadb9150285`,
  15,858 bytes.

## Upload proof (service-account create-only path)

- `gcloud storage cp` CANNOT work create-only: it pre-reads the destination
  (403 `objects.get` denied, observed twice) even without
  `--if-generation-match`. This also affects the stock script's immutable
  upload step as the SA — recorded, not changed.
- Uploaded instead via raw JSON API `POST .../upload/...?uploadType=media`
  with server-side `ifGenerationMatch=0` as the SA:
  `account-hardening/20261003T163300Z-first-a8f3c1/account-backup.tar.gz.age`,
  generation `1791045384597486`.
- Owner-side round-trip: re-downloaded to `C:\tmp\soak\verify-first.age`,
  sha256 matches byte-for-byte. Owner restore-read path proven.
- Host staging shredded (`/tmp/cv-hardening` gone, verified).

## Schedule

- Daily 02:00 UTC root cron on cv-web-ui:
  `/opt/ciphervault-ui/recovery-upload.sh` (same proven steps:
  backup → rehearse → tar → age → raw-API upload), log
  `/opt/ciphervault-ui/recovery-upload.log` (0600). Age v1.3.2 persisted
  at `/opt/ciphervault-ui/bin/age`. RPO 24 h.
- First scheduled run NOT yet observed — verify tomorrow with:
  `gcloud storage ls gs://cv-account-recovery-108687509435/account-hardening/`
  plus the tail of the upload log.

## Deliberate gaps (Path B limits)

- Retention is set, not locked. Lock only after owner re-authorization.
- No automated verify-side: decryption needs the owner's offline secret,
  which must never live on prod. Verification is a quarterly manual owner
  drill (below), not a timer.
- No alert destination approved yet: cron failures go only to the local
  log. Owner to name an alert channel (email/webhook) for stale/failure
  alerting.
- SA impersonation by the owner is impossible (empty SA IAM policy) —
  deliberately left that way.

## Owner decrypt drill (run quarterly, or on demand)

On the owner's machine with `keeper-key.txt` present:

1. `gcloud storage cp gs://cv-account-recovery-108687509435/account-hardening/<RUN>/account-backup.tar.gz.age .`
2. `age --decrypt --identity keeper-key.txt --output account-backup.tar.gz account-backup.tar.gz.age`
3. Untar, then `ciphervault-account restore-rehearsal --backup-dir <bundle>
   --output-dir <out> --kek-file <kek-copy> --totp-key-file <totp-copy>`
   (build the account binary via `cargo build --release -p
   ciphervault-account`; fetch KEK copies from Secret Manager; shred
   copies after). Expect `verified_isolated_restore`.
