# Account service security and scoped API



The account service has two confidentiality contexts. Original file-backup vault values and private keys stay on clients. Hosted scoped-secret values are received and decrypted by the account server under its configured KEK. Hosted scoped secrets are therefore not zero-knowledge to this service.



## Authentication and authorization

The [enforced MFA policy](../../docs/ENFORCED_MFA.md) adds explicit per-account
second-factor enforcement. Existing accounts remain optional until an owner
confirms an authenticator, retains recovery codes, verifies a fresh TOTP code for
the current primary session, and enables the durable policy. Sensitive guards
and scoped-token origin checks enforce it; handoffs carry no factor proof.
Emergency reset is full-account recovery and revokes all sessions. A recovery
code sheet remains recovery authority, not independent multi-party approval.



Sensitive human operations, account administration, recovery-code reissue, credential/device changes and scope-token issuance require signing-key or passkey authentication within five minutes. Signing-key possession is strong authentication for this policy; it is not itself a claim that two-factor MFA occurred. WebAuthn user verification is enforced only when `CIPHERVAULT_WEBAUTHN_REQUIRE_UV=true`; this runtime does not infer verified MFA from a standalone device session. Recovery sessions cannot mint credentials or mutate scoped state. TOTP alone remains an alternate login method; it does not establish strong MFA or production elevation. A browser handoff preserves the original authentication time, expiry, device and passkey revocation context. After recovery enrollment, the new device can answer a device-bound `/v1/sessions/challenge` using its enrolled signing key with the existing `account_login` proof domain. Account-root signing remains supported. Recovery enrollment alone does not upgrade the recovery session; a separate key-possession login is required.



Scope tokens expire after at most 15 minutes or the source session expiry, whichever comes first. Newly issued tokens are linked to the source session hash, so session logout and device/passkey revocation invalidate them. Production authorization never trusts a caller-provided branch string or a legacy branch-only token.



An authenticated human can explicitly request a production token:



```json

{

  "project_id": "<project ID>",

  "environment_id": "<production environment ID>",

  "elevated": true,

  "ttl_seconds": 300

}

```



Send this body to `POST /v1/scope-tokens` with a recent account session. Elevation lasts only until the original five-minute authentication window ends, even if the token has a later expiry. Repeat authentication when the service returns `AUTHENTICATION_STEP_UP_REQUIRED`.



Trusted CI/workload branch verification is **unavailable** in this runtime. Supplying `branch` returns HTTP 503 `WORKLOAD_ATTESTATION_UNAVAILABLE`. A future adapter must verify issuer signatures, audience, freshness, repository identity and immutable commit/ref evidence; self-declared branch names are insufficient.



Environment, repository and service restrictions cannot be dropped when authorizing a broader target. A restricted workload token cannot manage project memberships, invitations, repository bindings, audit exports or migration runs. Moves and rebindings authorize both the original resource and its destination. Resource associations must remain within the same tenant and project. Fresh human sessions derive exact resource context from server records, preserving legitimate administration of bound secrets.



Existing scope tokens without source-session claims can remain usable for their existing non-production scope until expiry. Rotate the scope-token signing key during rollout to revoke all earlier issuance. Rotation invalidates outstanding tokens and requires clients to authenticate and mint again.



Challenge issuance is limited across login/enrollment methods, accounts, request sources and the service as a whole. Quota reservations use atomic SQLite statements across independent service connections. Direct deployments share a conservative source budget unless trusted proxy identity is configured; configure proxy trust only when clients cannot reach the service outside that proxy.



## Atomic scope materialization



`GET /v1/projects/{project}/secrets?environment={environment}` returns metadata and a `revision` for exactly the returned set. Use `limit` to make the intended inventory explicit. `POST /v1/projects/{project}/environments/{environment}/materialize` accepts:



```json

{

  "names": ["DATABASE_URL", "API_KEY"],

  "expected_revision": "<optional 64-character revision>"

}

```



The response is:



```json

{

  "revision": "<64-character revision>",

  "values": [

    {"name": "API_KEY", "secret_id": "<ID>", "version": 2, "value": "<value>"},

    {"name": "DATABASE_URL", "secret_id": "<ID>", "version": 1, "value": "<value>"}

  ]

}

```



Names are unique and sorted in the response. All authorization checks, version selection, decryption and access audit entries share one SQLite transaction. No subset is returned or audited if an item is denied, missing, corrupted or too large. A changed revision returns HTTP 409 `SCOPE_REVISION_CHANGED`.



The revision pins the selected name/ID/version/binding/service/status set, not unrelated environment membership. The metadata revision can be used when the batch requests exactly the names in that list. For a subset, use the revision from a prior materialization of that same subset. One unpinned batch still observes a single consistent snapshot. Batches contain up to 100 names and at most 128 KiB of raw values. Empty batches still check authorization/revision and consume one quota unit. Each value consumes a read-quota unit; batching does not increase the exfiltration budget. Bound tokens can list and materialize only resources matching their restrictions.



## Versioned local KEKs



The existing `CIPHERVAULT_ACCOUNT_LOCAL_KEK` and `CIPHERVAULT_ACCOUNT_LOCAL_KEK_FILE` configuration accept the legacy 32-byte hex key. The file takes precedence. A versioned configuration also accepts:



```json

{

  "active_version": "v2",

  "keys": {

    "legacy": "<original 64-character hex KEK>",

    "v1": "<historical 64-character hex KEK>",

    "v2": "<new 64-character hex KEK>"

  }

}

```



`legacy` retains the original `local:{project}` identifier. Other versions use `local:{project}:{version}`. New versions use the active key; reads resolve the key identifier stored on each version. Unknown keys, malformed configuration and changes to key material under an existing identifier fail closed. The database records only a fingerprint for immutable identity, never raw KEK material. Existing databases establish their baseline by successfully unwrapping a historical DEK before recording the fingerprint.



Keep historical keys and database backups until all dependent versions, backups and replicas have been rewrapped and verified. Preserve configuration across restarts. This local implementation is not a managed KMS integration, and it does not replace independent key custody, access controls or backup/restore rehearsals.



After adding a new active version, a fresh human project admin can call `POST /v1/projects/{project}/keys/rewrap` with:



```json

{"reason": "scheduled KEK rotation", "limit": 100}

```



The bounded response contains `active_key_id`, `rewrapped` and `remaining`. Repeat until `remaining` is zero. Each batch unwraps historical DEKs, wraps under the active key and verifies the result before committing. Secret versions, value ciphertext and plaintext remain unchanged. Failure rolls back the entire batch. The operation is audited and requires a fresh human admin; workload tokens cannot initiate it. Re-running a completed operation rewraps zero records.



## Rotation and integration availability



`POST /v1/projects/{project}/secrets/{secret}/rotate` performs manual value replacement by default and returns `provider_verified: false`. Set `verify_provider: true` only when a provider adapter is available; the current runtime returns HTTP 503 `PROVIDER_VERIFICATION_UNAVAILABLE`. It does not create, revoke or validate credentials at an external provider.



Idempotency keys bind the principal, candidate digest, reason and verification mode. Replaying the same request returns its original previous/current version receipt, even after later rotations or restart. Reusing a key for different input returns HTTP 409 `IDEMPOTENCY_CONFLICT`. Historical rotation jobs without complete receipts also return that error; use a new request key instead of relying on an inferred outcome.



Repository ownership verification and reconciliation remain unavailable until a real provider client is configured. Proof requests return HTTP 503 `VCS_PROVIDER_UNAVAILABLE`, and unproven bindings remain suspended. Webhook verification and existing repository lifecycle controls continue to work; a webhook is not a substitute for provider ownership proof.



`GET /v1/capabilities` reports available behavior and these external integration limits explicitly. No live credentials, deployed accounts or production databases are required for local regression tests.
