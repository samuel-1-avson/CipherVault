# CipherVault production rollout verification — 2026-09-15

## Deployed

- Uploaded source-only archive: `ciphervault-dashboard-source-20260915.tar.gz`
- Archive SHA-256: `ABF8906E48CBB8474F7874DC47F2CF0DDAE637E2BDA8BF461136EA0F8E6325A7`
- Dashboard image: `ciphervault-ui:pooled-20260915`
- Image digest: `sha256:78bee5bf734452dbf0755d0548a9e4c985b44c95bee7fafcbfd84fa930a244b3`
- Container: `ciphervault-ui-ciphervault-ui-1`
- Health: `healthy`
- Rollback compose file: `/opt/ciphervault-ui/docker-compose.rollback-20260915.yml`

The dashboard is serving the pooled HTTP client, persisted collector job history, and independent identity-pinning code. Caddy remained running during the dashboard replacement.

## Verification evidence

- `https://vault.cipherv.online/` returned HTTP 200 over HTTPS.
- `/api/context` reports `mode: public_explorer` and keeps vault files, snapshots, recovery, and administrative capabilities disabled.
- `/api/operators` reports 3/3 reachable operators. The public explorer reports latency and reachability only.
- `/api/operators/jobs` returns retained successful collector runs with operator and reachable counts.
- `/api/snapshots` returns HTTP 403 with `PRIVATE_API_DISABLED` from the public endpoint.
- `/api/relayer/checkpoints` correctly reports that no signed public checkpoint feed is configured.
- The live UI reports `Telemetry stream: Active`, no browser console errors, 3/3 operators responding, and retained probe/job history.

## Identity and checkpoint status

The operators currently return public signing keys, but their deployed `/v1/info` responses do not contain a valid self-signature. The dashboard therefore correctly shows `identity_verification: unverified` and `identity_trust: not_pinned`. The observed keys must not be promoted to trusted production fingerprints until operator key rotation and independent verification are complete.

No production signed checkpoint feed or finality receipt is configured. The publisher profile is present in compose, but no publisher container is running and no signing key/evidence has been provisioned.

## Remaining work

1. Rotate operator signing keys, deploy the signed `/v1/info` identity documents, and pin independently verified fingerprints.
2. Provision the signed public checkpoint feed, key pinning, and independently verifiable finality receipts.
3. Complete vault-scoped device enrollment, session expiry/revocation, and route authorization tests on the operator fleet.
4. Deploy regional collectors or relocate collection to reduce the cross-region latency floor for operators 1 and 2.
5. Finish durable event/retry/alert persistence and recovery-drill persistence.
6. Apply rate/concurrency limits, private firewall policy, mTLS, and production key-file permission checks to the operator fleet.
7. Finish owner workflows and run the clean Docker, readiness, accessibility, and rollback validation suite.

Docker was not installed in the local Windows workspace, so the image build was validated on `cv-web-ui` rather than with a local Docker daemon.

## Deployment preflight (2026-09-15 local workspace)

The requested follow-up rollout could not be started from this workstation. The
preflight stopped before any cloud mutation because:

- Docker is unavailable (`docker` is not installed or on `PATH`).
- The gcloud profile has no active authenticated account; an isolated config
  returned an empty account list and no active project.
- No `CIPHERVAULT_*` production signing, operator identity, checkpoint-feed, or
  service-token variables are present in the deployment shell.
- The local Windows recovery drill still cannot open a functioning keystore:
  DPAPI returns `CryptProtectData failed`.

The PowerShell GCP provisioner was syntax-checked and its parameter separator
was corrected, but it was not run because the required cloud credentials and
keystore are absent. The existing HTTPS deployment record above remains the
previous image; it does not include the current uncommitted account, passkey,
membership, recovery, and collector changes.

## Follow-up changes pending rollout

After the deployment recorded above, the workspace added the hosted account
proxy and browser passkey ceremony (`/api/account/webauthn/*`), account
invitation/membership routes, and one-time recovery-code routes. These changes
are validated locally but are not included in the image digest above. A new
cloud rollout must be performed after cloud credentials and the production
account/operator secrets are available.

## Live read-only verification (2026-09-15)

The existing `https://vault.cipherv.online/` deployment loaded successfully in
the in-app browser. It reported 3/3 operators responding, 25 ms average cluster
latency, 288 historical probe samples, and 489 retained collector runs. It also
reported `identity unverified`, no retention receipt, and no verified
checkpoint. The new hosted passkey/account controls were absent, consistent
with the older image still running in production.

## CLI TUI release preflight (2026-09-15)

The latest pooled-client TUI release build completed successfully. The final executable is available at `dist/bin/ciphervault-tui-fixed.exe` and the packaged Windows x86_64 artifact is `dist/ciphervault-tui-1.0.0-windows-x86_64.zip`. SHA-256: `5C14BCEAC603F510D9D800E04916B50573ACD6CC57D806B3BE1AEAA2B2936C44`. `--version` reports `ciphervault 1.0.0`.

The tracked `dist/bin/ciphervault.exe` cannot be replaced while the currently running TUI process (PID 34136) has it open. The replacement is a local release artifact; once that process exits, the artifact can be copied over the main executable.

This is a local build/package only. No GitHub release, cloud VM rollout, or production artifact publication was completed in this session. Production remains on the older dashboard image described above.

## Deployment attempt (2026-09-15, current session)

A fresh source-only archive was prepared at `dist/ciphervault-source-20260915.tar.gz` (SHA-256 `0CEB9640E0459ED02334EAFD466CA5D110F65FD13D72E3F3B81E7E0DEA15D890`). It contains the current working-tree source, including the updated TUI, account service, operator changes, and deployment definitions, while excluding `.git`, `dist`, local vault state, secrets, recovery shares, operator runtime data, and build targets.

The rollout could not be executed: Docker, Docker Compose, Podman, and nerdctl are unavailable; the isolated gcloud configuration has no authenticated account or project; and no production `CIPHERVAULT_*` secrets or functioning keystore are present. No cloud mutation was attempted.

Packaged TUI ZIP SHA-256: `D5707663C20AFE2200A41DE8E438854E903908E1822CC276D0B8D88E3808E662`.
