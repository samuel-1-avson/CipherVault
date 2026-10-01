# Recovery custody implementation and remaining evidence

Date: 1 October 2026 (UTC / Africa/Accra).

**Outcome: custody automation is implemented and locally verified; independent
production custody remains pending actual destination and custodian selection.**
No cloud policies, production data, key material, live timers, or external
notifications were changed by this work.

## Delivered

| Area | Concrete behavior |
| --- | --- |
| Safe configuration | Default offline preflight; exact separate destination/project required; existing absolute paths; owner-only outputs; no symlink/reparse paths; expired/false custody attestations fail |
| Destination checks | Read-only raw GCS bucket policy checks for exact project, uniform access, public-access prevention, object versioning, locked minimum retention; rejects direct public/declared-production-admin IAM grants |
| Split backup and rehearsal | Production upload-only mode: local rehearsal + age encryption + create-only upload; separate custodian receiver: encrypted-copy SHA/size check + decryption + isolated rehearsal without a production source path |
| Metadata protection | Optional standard age X25519 whole-archive encryption/decryption CLI; omission explicitly reports GCS-at-rest-only metadata protection |
| Key handling | Existing key paths used locally; no values printed/archived; no key overwrite or deletion; expiring historical-version/key-custody receipt required |
| Failure monitoring | Non-zero status for stale/no evidence, latest failure/interruption, invalid history, changed configuration or custodian records; older success cannot mask newer failure |
| Local capacity | Free-space guard before backup and after receipt; retains artifacts and never prunes keys/history to create room |
| Provisioning | Exact gcloud argument plan with chosen defaults; required real separate human identities/billing/review; no execution path; separately marked irreversible retention-lock phase |
| Scheduling | Eight inactive two-host backup/verification/status templates; no cloud or host scheduler activated |

The runner reports `independent_custody_certified: false`. Governance labels and
unsigned attestations are administrative records. They cannot prove inherited
IAM separation, transitive group isolation, or the actual existence of an
independent key copy. Those are explicit human/operational acceptance items.

## Verification

Command executed locally:

```powershell
$env:CIPHERVAULT_ACCOUNT_TEST_BINARY='C:/Users/samue/.cargo-targets/ciphervault/debug/ciphervault-account.exe'
python -m unittest discover -s tests/recovery -v
```

**30 tests passed, 0 failed, 0 skipped** on this Windows workstation. This includes
real Windows DACL output protection and the existing compiled v1.0.26 account
CLI against a newly initialized synthetic database: its invalid bind prevented
HTTP startup, backup succeeded, the archive was safely unpacked, isolated restore
verified, and the original database checksum remained unchanged. No live
account database or cloud credential was used.

Synthetic adapters exercise same-project/governance rejection, missing or
expired historical-key custody, wrong bucket ownership, weak retention/privacy,
public/production IAM bindings, upload create-only conditions, altered downloads,
unexpected archive/key entries, path traversal, symlink archive entries, changed
attestations/configuration, stale/interrupted status, concurrency locking, native
output suppression, and age CLI wiring.
Additional split-flow fixtures prove the production uploader never reads/lists
objects or needs the age private identity, the receiver accepts no production
source and never uploads, a failed receiver checksum prevents decryption/drill,
and provisioning plans reject shared/unknown/expired governance identities.
An additional internal pass replaced eager tar-member enumeration with fixed
USTAR header parsing and aggregate expanded-byte limits. Regressions reject
thousands of extra members, oversized declared bodies and extended headers
before reading those bodies, as well as excessive zero padding. Native stdout
is bounded during capture, stderr is discarded, and subprocess timeout/output
overflow tests execute real synthetic child processes. Cloud-history listing
cannot accumulate output beyond the capture limit; exceeding it fails closed
and requires a narrower explicit-object verification or reviewed listing policy.

The age test uses an explicitly synthetic adapter. It verifies encryption and
decryption command wiring, archive selection, and the copy/rehearsal flow; it
does not certify the real age executable or real recipient interoperability.
The cloud policy/copy tests also use synthetic fixtures. Live GCS and deployed
Linux timer validation must run against the selected custodian destination.

## Chosen architecture and reviewable provisioning

The user's instruction to choose the best architecture is implemented with
explicit defaults: separate project `cv-recovery-108687509435`, private bucket
`cv-account-recovery-108687509435`, EU multi-region, versioning, 30-day locked
retention, age whole-archive encryption, production object-create-only workload,
read-only restore custodian, and distinct offline historical-key custodians.
Production upload is scheduled for 02:00 UTC and independent verification for
03:00 UTC, with separate freshness checks every 15 minutes. These schedules
are templates, not active jobs.

Read-only GCP queries confirmed production project `gen-lang-client-0022105784`
has number `108687509435`, and the existing workload identity
`cv-web-runtime@gen-lang-client-0022105784.iam.gserviceaccount.com` exists.
No actual custodian email/principal, parent/billing owner, or archive recipient
was supplied; these cannot be invented while preserving independent ownership.

The [provisioning configuration](../scripts/recovery/provisioning.example.json)
and [plan generator](../scripts/recovery/plan_provisioning.py) make the selected
resource and permission changes concrete. The generator never executes commands
and refuses unresolved/shared identities or missing governance review. Actual
project creation, IAM grants, billing linkage, and retention lock remain inactive
because independent control is not verified. No repeat architecture decision is
needed; the remaining inputs identify real custodians and their authority.

The [custodian receiver](../scripts/recovery/receive_custody.py) runs on its
separate configured host using its own protected historical key files. Missing
keys prevent scheduled rehearsal; automation does not authorize copying offline
escrow to an unattended host. The selected uploader needs only the age public
recipient and existing production account keys for its local drill.

## Existing production evidence

The [September 30 ledger](DEPLOYMENT_2026-09-30.md) records two protected account
backups, successful isolated restores, a matching off-host archive download, and
separately retained local keys. The bucket is in the production GCP project.
Those facts remain useful recovery evidence and are preserved; they do not
satisfy independent organizational custody. The live restore had one TOTP seed
and no retained scoped-secret versions, so it could not prove live historical
secret-value recovery. That limitation remains explicit.

## External requirements to close the gap

1. Supply the actual separately administered GCP project/bucket, owner, IAM
   review reference, approved minimum retention, and backup workload identity.
   A different project under the same destructive administrators is insufficient.
2. Name separate offline key custodians, retain required historical versions and
   archive identity through a protected manual ceremony, and record an
   independent clean-machine restore reference. No keys should be sent in chat.
3. Run real read-only bucket preflight, then the first explicit private backup
   copy/rehearsal, including a retained-secret fixture and real age identity if
   enabled. Independently confirm the destination archive and evidence record.
4. Validate and activate deployment-specific timers and an approved alert
   destination; demonstrate stale/failed alert delivery and measure recovery
   point/time. Current templates are deliberately inactive.
5. Separately anchor backup authenticity, establish reviewed storage cleanup,
   and retain historical keys for every surviving backup. This runner performs
   no destructive pruning and will need local capacity monitoring.

See [the custody runbook](../docs/INDEPENDENT_RECOVERY_CUSTODY.md),
[the runner](../scripts/recovery/account_custody.py), and
[the fixture suite](../tests/recovery/test_account_custody.py).
