# Independent recovery custody: activation checklist

The custody automation is implemented and tested (38/38 recovery tests pass,
including one against a real account binary). What remains is operational:
independent administration cannot be created by the production operator. Do
each step in order; no step executes cloud changes except where marked HUMAN.

## 0. Name the humans (out of band)

Record, outside chat: recovery-project owner, IAM review reference owner,
billing/parent owner, backup workload identity owner, and two offline key
custodians. Never send key material in chat. A second project under the same
destructive administrators does not qualify.

## 1. Render the provisioning plan (no execution)

```sh
cp scripts/recovery/provisioning.example.json /owner/only/custody-provisioning.json
# Fill every REPLACE_WITH identity, billing account, and review reference.
python scripts/recovery/plan_provisioning.py \
  --config /owner/only/custody-provisioning.json --output /owner/only/plan.json
```

The planner refuses shared, unknown, or expired governance identities. Target
defaults: project `cv-recovery-108687509435`, bucket
`cv-account-recovery-108687509435`, EU, uniform access, public-access
prevention, versioning, 30-day retention, age whole-archive encryption,
production object-create-only workload, read-only restore custodian.

## 2. HUMAN: create the destination, then lock retention separately

A recovery-side administrator executes the plan's creation steps, then the
retention-lock phase only after custodian review. Retention lock is
irreversible; it is deliberately a separate step.

## 3. Read-only destination preflight

```sh
python scripts/recovery/account_custody.py --config /owner/only/custody.json --online
```

Pass criteria: exact separate project/bucket, uniform access, no public or
production-admin IAM grants, versioning on, locked minimum retention met.
Anything else fails closed; fix the destination, not the check.

## 4. First private backup copy and isolated rehearsal

On the production host (upload-only, no object-read permission needed):

```sh
python scripts/recovery/account_custody.py --config /owner/only/custody.json --upload-only
```

On the separate custodian host with its own protected historical keys:

```sh
python scripts/recovery/receive_custody.py --config /owner/only/receiver.json
```

Include a retained-secret fixture so the drill proves secret-value recovery,
not just metadata restore (prior rehearsals had zero secret versions). Keep
the receipt: object generations, SHA-256 hashes, and the rehearsal report.

## 5. Activate schedules and alerting

Adapt the eight `scripts/recovery/*.example` systemd templates to the two
hosts (02:00 UTC upload, 03:00 UTC verification, 15-minute freshness checks),
wire the approved alert destination, then demonstrate a stale evidence alert
and a failed-verification alert end to end. Measure and record RPO/RTO.

## 6. Declare activation only with evidence

Set `custody_activated` only when: separate administrators confirmed by
independent IAM review, retention locked, clean-machine restore witnessed,
timers live, and both alert demonstrations recorded. Until then the deployment
report's `custody_activated: false` stands.
