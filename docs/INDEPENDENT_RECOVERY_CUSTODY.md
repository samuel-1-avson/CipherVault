# Independent recovery custody

Updated: 1 October 2026 (UTC / Africa/Accra).

The account backup runner is ready for a separately administered destination.
No independent destination, custodian, live schedule, or alert recipient has
been provisioned by this change. Existing September 30 backups remain in the
production GCP project and in a protected workstation folder. They provide
verified copies, but they do not establish independent custody.

## Recommended ownership model

Use a separate GCP project controlled by a backup custodian who cannot administer
production, with a private bucket, object versioning, and a locked retention
policy. The selected defaults are project `cv-recovery-108687509435`, bucket
`cv-account-recovery-108687509435`, EU multi-region, 30 days of protected history,
daily production upload at 02:00 UTC, daily independent verification at 03:00 UTC,
and separate freshness checks every 15 minutes. EU places the custody copy away
from the existing US production fleet. Project and bucket names are planned,
not already provisioned or guaranteed available.
Separately named offline key custodians retain every required KEK version,
the TOTP wrapping key, and the archive decryption identity. Keep key material
outside the database-backup bucket. The disaster runbook must also support fresh
scope-token signing keys and provider credentials before exposing a restore.

A separate project number alone does not establish independent administration.
The custodian must review inherited organization/folder IAM, transitive group
membership, service-account impersonation, billing/project deletion authority,
and break-glass access. Production administrators must not be able to destroy
the destination or the retained keys. Record the review and an independent
restore ceremony in the expiring attestations described below.

The production workload receives **object-create-only** access plus a narrow
custom bucket-policy-reader role. It receives no object read/list/delete access.
The independent restore custodian receives object-read/list access and policy
read access, with no upload/delete grant. Production must not modify retention,
change bucket IAM, or administer the destination project. Provision short-lived
credentials for that workload rather than copying an interactive administrator
login or a long-lived service-account credential into this repository.

## Concrete provisioning plan

[provisioning.example.json](../scripts/recovery/provisioning.example.json)
contains the selected defaults. Read-only GCP checks on October 1 confirmed
production project number `108687509435` and the existing workload identity
`cv-web-runtime@gen-lang-client-0022105784.iam.gserviceaccount.com`, used as the
planned uploader. This does not grant that identity any new permission.

[plan_provisioning.py](../scripts/recovery/plan_provisioning.py) renders exact
gcloud argument arrays for separate-project creation, approved billing, private
bucket creation, versioning, explicit custodian IAM grants, uploader permissions,
and retention locking. It has **no execution or Apply operation**. Terraform is
not installed in the current workspace; no provider installation is required.

Fill actual independently controlled custodian principals, billing/parent
authority, an age public recipient, and a current governance-review reference
before rendering a plan:

```sh
python3 /opt/ciphervault/scripts/recovery/plan_provisioning.py \
  --config /etc/ciphervault/provisioning.json \
  --output /var/lib/ciphervault-custodian/provisioning-plan.json
```

The generator rejects placeholders, shared listed production/custodian
identities, shared offline-key/backup identities, expired review, or an unapproved
independence statement. It does not invent people, email addresses, or billing
ownership. Every planned command pins the supplied independent provisioner's
account. With both parent fields null, the plan creates a standalone project
under that account; an actual reviewed independent organization/folder can be
supplied instead. [Project creation semantics](https://docs.cloud.google.com/sdk/gcloud/reference/projects/create).

The retention-lock command appears as a separate `irreversible_retention_lock`
phase after bucket and IAM inspection. The new project, billing, IAM, and locked
retention remain planned because actual independent ownership has not been
verified. Review/apply them under the real custodian account; no live creation
or policy mutation was attempted here. A locked period cannot be reduced or
removed. [Bucket retention locking](https://docs.cloud.google.com/sdk/gcloud/reference/storage/buckets/update).

## Tools and configuration

[account_custody.py](../scripts/recovery/account_custody.py) requires Python 3.11
or later, the released `ciphervault-account` binary, and `gcloud`. Optional
whole-archive encryption uses the standard `age` executable. The runner accepts
GCS destinations; other providers require a separately reviewed adapter.

Copy the three example documents into an owner-only configuration directory
outside the checkout and OneDrive:

- [custody.example.json](../scripts/recovery/custody.example.json): absolute
  executable/data/key paths, production and destination project numbers,
  governance identifiers, prohibited production admin principals, thresholds,
  and the explicit destination bucket/prefix.
- [destination-attestation.example.json](../scripts/recovery/destination-attestation.example.json):
  destination identity, custodian review reference, deletion-authority statement,
  and a UTC expiry timestamp.
- [key-custody-receipt.example.json](../scripts/recovery/key-custody-receipt.example.json):
  historical KEK **version labels**, TOTP/archive-key retention confirmation,
  scope-signing-key rotation readiness, and an independent restore reference.

These examples intentionally contain invalid placeholders and expired or false
attestations. They cannot turn on custody by being copied unchanged. Never put
private key values, login tokens, provider credentials, or recovery shares into
these documents. Governance identifiers are administrative labels, not an
authentication mechanism. Attestations are unsigned human records; their hashes
detect a changed document and do not authenticate a custodian.

On Unix, the configuration and key files must be owned by the runner user with
no group/other permissions. The existing work directory must be owner-only and
outside the production data directory. On Windows the runner requires protected
DACLs granting access only to the current user, Administrators, and SYSTEM. All
configured paths reject symlinks/reparse points. Do not relocate, overwrite, or
delete existing historical key material while preparing the configuration.

The account binary must come from the authenticated release bundle or an
independently verified build. The runner does not replace release signature
verification. Resolve executable paths to actual files before configuration.

For whole-archive encryption, provision a custodian-controlled age X25519 public
recipient and separately protected identity. On production, set `identity_file`
to `null`: production needs only the public recipient. The independent receiver
requires its controlled identity file. Key custodians retain offline copies and
release protected read-only key paths for the drill under their agreed policy;
missing key files fail the drill. Do not silently move offline escrow into an
always-on host to make scheduling pass. Identity files and KEKs are never
archived. Set `archive_encryption` to `null` only if the custody policy accepts
GCS encryption at rest: account metadata then remains readable to authorized
bucket readers. The encrypted secret fields alone do not encrypt the entire
account database. [age documentation](https://github.com/FiloSottile/age).

## Preflight, run, and monitor

The default invocation validates local configuration and does not read key
contents, create backup output, execute maintenance commands, or call the cloud:

```sh
python3 /opt/ciphervault/scripts/recovery/account_custody.py \
  --config /etc/ciphervault/custody.json
```

Add `--online` to perform read-only destination checks. It reads raw bucket
metadata and bucket IAM. It requires the configured destination project to
differ from production, uniform access, public-access prevention, versioning,
and an already locked retention period of at least the configured minimum.
Direct grants to public principals or explicitly listed production admin
principals fail the check. Inherited grants, group expansion, and organization
ownership still require the custodian's review. The runner never creates a
bucket, changes IAM, or locks a retention policy.
[Raw bucket metadata](https://docs.cloud.google.com/sdk/gcloud/reference/storage/buckets/describe),
[bucket policy fields](https://docs.cloud.google.com/storage/docs/json_api/v1/buckets).

The selected production operation is:

```sh
python3 /opt/ciphervault/scripts/recovery/account_custody.py \
  --config /etc/ciphervault/custody.json --upload-only
```

It backs up and locally rehearses the data, encrypts the complete archive to the
custodian's age public recipient, then creates a unique archive and non-secret
producer evidence object. It never downloads or lists objects and never uses
an age private identity. Its success state is
`uploaded_pending_independent_verification`, with `copy_verified: false`.
Production upload success is not independent recovery evidence.

The independently controlled host uses
[custodian.example.json](../scripts/recovery/custodian.example.json) and
[receive_custody.py](../scripts/recovery/receive_custody.py):

```sh
python3 /opt/ciphervault/scripts/recovery/receive_custody.py \
  --config /etc/ciphervault/custodian.json --verify-latest
```

The receiver requires `data_dir: null`, so a production source cannot be
configured. It lists producer evidence in the configured prefix, reads the
latest unique receipt/archive, enforces object-size and path limits, verifies
the encrypted archive hash, decrypts it using the custodian identity, safely
unpacks it, and runs the account isolated-restore command with separately
retained historical keys. Its local state is
`verified_received_archive_and_isolated_restore`; it never uploads a cloud
object or promotes the restored database. Specific historical objects can be
rehearsed with `--object` and an explicitly supplied `--expected-sha256`.
The configured artifact ceiling defaults to 1 GiB for the archive and aggregate
expanded database/receipt bytes. Archives use the runner's fixed USTAR format;
PAX/GNU extensions, links, duplicate/extra entries and excessive padding are
rejected before unbounded metadata or entry-body processing.

The earlier combined runner remains useful for a controlled copy/rehearsal
test using a principal authorized for both upload and download:

```sh
python3 /opt/ciphervault/scripts/recovery/account_custody.py \
  --config /etc/ciphervault/custody.json --apply
```

It acquires a process lock, creates a new protected run directory, rechecks cloud
policy, then executes this sequence:

1. Create a consistent account backup using the existing offline maintenance
   command. Verify its database checksum/receipt and reject unexpected files.
2. Rehearse that backup in a new isolated directory with separately supplied key
   paths. Require an authenticated plaintext/audit/database verification result
   from the account command.
3. Archive only `accounts.sqlite3` and `backup-receipt.json`; optionally encrypt
   the whole archive with age. No key files or rehearsal database are included.
4. Upload to a unique object with `--if-generation-match=0`, preventing overwrite.
   Download it, require identical SHA-256/size, decrypt if configured, and reject
   links, unexpected entries, or unsafe archive paths during unpacking.
5. Rehearse the downloaded bundle in another new directory. Publish a protected
   completion record and upload that non-secret evidence next to the archive.

The runner invokes the existing maintenance subcommands directly; they never
start an HTTP listener. The runner itself needs network access for cloud copy
operations and does not create a separate network namespace for its child
processes. Deployment-specific isolation can add stronger confinement. It never
mounts a rehearsal directory as the production database or promotes a restore.

Native stdout is capped at 1 MiB while it is read; excessive output terminates
the command. Native stderr is discarded, and a configured timeout bounds command
execution. Native output is suppressed from reports. Reports contain hashes,
timestamps, counts, destination references, and fixed failure descriptions.
Key **paths** are passed to the maintenance CLI, never key contents. Unexpected
exceptions also produce a fixed description. Failed runs retain private output
for diagnosis; missing keys, corruption, wrong destination policy, failed copy,
failed rehearsal, or expired attestations prevent a successful result.

Monitor with:

```sh
python3 /opt/ciphervault/scripts/recovery/account_custody.py \
  --config /etc/ciphervault/custody.json --status
```

For the selected split model, production uses `--upload-status` to monitor only
its upload freshness; the independent host uses `receive_custody.py --status`
with its custodian configuration to monitor actual downloaded restore evidence.
Both stages must be healthy. A production upload status cannot clear a failed
or missing independent verification.

The command exits non-zero for no completed backup, stale data, a latest failed
or interrupted run, malformed history, or changed configuration/attestation.
Age is measured from the database backup timestamp, not the last status check.
An older successful backup cannot hide a newer failed run. Local reports are
unsigned operational evidence, not a proof against a compromised host.

## Schedule activation

The eight `*.service.example` / `*.timer.example` files in
[scripts/recovery](../scripts/recovery) provide inactive Linux systemd templates:
daily production upload at 02:00 UTC, independent-host verification at 03:00 UTC,
and status checks on each host every 15 minutes. They use separate service users,
owner-only output, read-only source/key paths, separate gcloud configuration,
and restricted writable output paths. Adapt
absolute paths and credentials to the actual deployment, validate with
`systemd-analyze verify`, and connect failures to an approved monitoring handler.

The example freshness threshold is 25 hours, allowing a daily schedule's bounded
jitter. Set the business recovery point first and adjust both timer and threshold
together. Do not enable timers until a real explicit run and status check pass,
the custodian confirms receipt, and alert delivery has been tested. No timers
or notifications were installed or enabled by this implementation.

## Acceptance and retention

Independent recovery custody remains open until all of the following are proven:

- Named destination owner and separate project; independent-admin review covers
  inherited IAM and destructive/break-glass authority.
- Retention/versioning/privacy checks pass against that real bucket, the first
  archive round-trip verifies, and whole-archive encryption interoperates with
  the real custodian recipient if configured.
- Named separate key custodians verify every retained historical KEK, TOTP key,
  and archive identity; a clean machine recovers a retained-data fixture while
  production access is unavailable.
- Scheduled runs and a deliberately stale/failed run generate the agreed alert;
  measured recovery point and recovery time meet the selected targets.
- A separately retained integrity/authenticity record anchors backup provenance.
  The account receipt and unsigned local run report alone are insufficient.

The runner never deletes archives, database history, rehearsals, or key versions.
Agree a separate reviewed retention/cleanup policy after validating dependencies
between retained backups and historical keys. Monitor local output capacity:
each run retains the backup, two rehearsal directories, archive, downloaded
copy, and, with age enabled, a decrypted copy for verification. Compression does
not make retained local storage unboundedly cheap.
Before backup and again after the receipt is available, the runner checks free
work space against ten times the estimated database size plus 64 MiB. A live WAL
is included in the initial estimate. This conservative guard does not enforce
a quota or guarantee that concurrent writers cannot consume the remaining space.

This procedure covers hosted account/scoped-secret data. Client-vault offline
recovery, operator data, infrastructure configuration, hardware-token ceremonies,
and independent cryptographic review remain separate requirements. See
[account maintenance semantics](ACCOUNT_BACKUP_AND_RECOVERY.md) and the
[September 30 deployment ledger](../report/DEPLOYMENT_2026-09-30.md).
