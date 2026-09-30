# Account control-plane backup and recovery

The account service now provides offline maintenance commands that create a
consistent SQLite backup and rehearse recovery into a new, isolated directory.
These commands never start an HTTP listener. They print counts and verification
results, never secret values or key material.

This procedure covers the hosted account/scoped-secret database. Client vault
recovery remains a separate ceremony.

## Create a backup

Run as the service's operating-system user. The source must already exist. The
output directory must **not** exist, and its parent must exist:

```sh
ciphervault-account backup \
  --data-dir /var/lib/ciphervault-account \
  --output-dir /var/lib/ciphervault-backups/accounts-2026-09-30
```

The backup uses SQLite's online backup API with a pinned read transaction. It
includes committed WAL changes while the service is running, rather than
copying a potentially stale database file. It creates owner-only output files
and a directory with mode 0700 on Unix, or a protected current-user DACL on
Windows. A 120-second limit bounds the copying stage. Long-lived read snapshots
can temporarily increase the live WAL; schedule large backups when traffic is
low and monitor free disk space.

The bundle contains:

- `accounts.sqlite3`: a self-contained database with no required WAL sidecar.
- `backup-receipt.json`: SHA-256, size, selected table counts, creation time,
  and the number of audit chains verified.

The command verifies SQLite integrity, foreign keys, the expected account
schema, and every scoped-secret audit chain before publishing the receipt.
An unsuccessful operation can leave a protected directory for diagnosis. A
bundle without a valid receipt is incomplete and must not be promoted.

The backup does **not** contain KEKs, TOTP wrapping keys, the scope-token
signing key, provider credentials, or external infrastructure. Retain those
separately in access-controlled secret storage, including every historical
KEK version still referenced by a retained secret version. A database backup
without these keys cannot recover encrypted values or TOTP authentication.

## Rehearse an isolated restore

Supply key **file paths**, rather than putting key values in shell arguments:

```sh
ciphervault-account restore-rehearsal \
  --backup-dir /var/lib/ciphervault-backups/accounts-2026-09-30 \
  --output-dir /var/lib/ciphervault-rehearsals/accounts-2026-09-30 \
  --kek-file /run/secrets/account-local-kek \
  --totp-key-file /run/secrets/account-totp-key
```

Both key arguments are optional for an empty installation. They become
mandatory when the database contains secret versions or TOTP credentials,
respectively. The KEK file accepts the same legacy hexadecimal or versioned
JSON format as the account service. Key files are limited to 64 KiB. Backup,
restore, and key paths reject symlinks and Windows reparse points.

The restore checks the receipt, copied database checksum, integrity, foreign
keys, inventory counts, and audit chains. It authenticates and decrypts every
retained scoped-secret version, including values preserved under an earlier
environment after a scope move. It checks each plaintext digest and decrypts
every retained TOTP seed. Plaintext verification stays in memory; temporary
plaintext buffers and supplied key-file text are zeroized on drop.

The copied database's sessions are revoked and its login challenges, handoffs,
and DPoP replay entries are deleted. The source database and backup bundle are
unchanged. Only complete success creates `rehearsal-report.json` with status
`verified_isolated_restore`, counts, and `production_modified: false`.
Wrong/missing historical keys, malformed envelopes, audit corruption,
checksum mismatches, and existing output directories fail closed.

## Promotion and retention

Keep the rehearsal offline. Successful verification is evidence that this
bundle and these keys recover the retained data; it does not authorize replacing
the production volume or establish that the newest production state was backed
up. Promote only through the deployment runbook with the service stopped,
the previous volume retained, and its rollback path verified.

Before a real disaster-recovery promotion, rotate the scope-token signing key
and external provider credentials. Restoring an earlier database can restore
earlier membership/device states, recovery-code use, denylist entries, and
revocations. Revoking copied sessions prevents their reuse, including new
session-bound scoped tokens, but cannot invalidate old stateless tokens without
rotating their signing key. Require fresh account authentication and reconcile
post-backup revocations before exposing the restored service.

The receipt is an **unsigned corruption check**, not an authenticity proof.
Protect the entire bundle with encrypted off-host storage, restricted access,
and an independently authenticated retention channel. A local database or
receipt attacker can rewrite both, and the unkeyed audit chain cannot prove
authenticity after complete rewriting. Keep externally anchored audit receipts
and deployment identity evidence separately. Monitor retention, age, recovery
point, recovery time, and disk capacity; this command does not schedule backups
or guarantee provider durability.

Intentional crypto-shredding and pre-envelope legacy versions can make some
retained values unrecoverable. The full drill reports failure in that case;
it never silently skips an unreadable retained version or claims complete
recovery.

## Authentication policy still required

Fresh signing-key/passkey sessions gate sensitive operations. TOTP login is
currently an alternate login method and is **not** a verified second factor.
An enforced MFA implementation must bind a one-time TOTP step-up to an existing
fresh device/passkey session, record factor time in that session, recheck it in
every sensitive guard and scoped-token origin lookup, and invalidate it on
credential revocation or handoff. Passkey user-verification policy alone is not
evidence that two independent factors were enforced. Enrollment/bootstrap and
recovery need explicit policy so enforcement cannot silently lock out existing
accounts or authorize credential replacement with TOTP alone.
