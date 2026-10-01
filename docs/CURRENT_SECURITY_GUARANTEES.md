# Current security and operational guarantees

Updated 1 October 2026. This describes the working implementation, not independent cryptographic certification or a claim that unpromoted changes run in production. Run current checks and review their actual results before release.

## Chunk versions and deployment gate

The default writer remains **legacy chunk v1** pending independent review of v2. Set `CIPHERVAULT_CHUNK_V2_WRITE=1` explicitly to opt into v2 captures. Unset or exactly `0` selects v1; empty, other or non-Unicode values fail capture before file processing. Library callers can pass `ChunkWriteVersion` explicitly to `create_snapshot_with_write_version` or `create_snapshot_with_signer_and_write_version`, avoiding process environment changes. Readers accept v1 and v2 independently of this gate and reject unknown chunk versions. Recovery records, certificates and encrypted manifests retain protocol version 1.

V1 preserves historical IDs, KDFs and ciphertext addresses. Its public complete-file identifier permits an operator to confirm a candidate file using public vault/epoch fields. V1 also binds chunk encryption to the whole file version, preventing encrypted reuse across edits. These limitations remain in default captures and existing remote history; enabling v2 does not rewrite old objects.

Opt-in v2 uses HKDF-SHA256 for keyed opaque file/chunk identifiers and separately derived chunk keys/nonces, with explicit version, domain, vault, epoch and identifier bindings. Unchanged padded chunk content has the same ciphertext CID within one vault and epoch, including chunks shifted by an insertion or repeated in one file. Cross-vault and cross-epoch reuse is deliberately excluded. Content-defined boundaries can change around an edit; no fixed deduplication percentage is promised. Small files receive a 4 KiB padding floor. The encrypted manifest authenticates file order, raw/padded lengths and the whole-file digest.

Operators without epoch keys cannot compute v2 opaque IDs from public candidate hashes. They still observe chunk equality within an epoch, ciphertext lengths, object counts, vault/epoch identifiers, traffic and access patterns. Compromised keys or an encryption oracle can restore candidate-confirmation ability. Deterministic encryption is therefore not a claim of semantic security without equality leakage. Exact derivations and compatibility boundaries are in [CHUNK_PROTOCOL_V2.md](../crates/snapshot/CHUNK_PROTOCOL_V2.md).

## Capture and restore

Capture rejects traversal, linked/reparse-point paths, nonregular files and files above 256 MiB before unbounded allocation. It bounds reads, checks opened-handle and pathname metadata before/after, and hashes the bytes actually captured. This detects ordinary concurrent edits; metadata checks are not an OS transaction or a defense against a privileged attacker deliberately restoring metadata and racing ancestor replacement.

Restore decrypts and verifies every file before publication, preflights destinations, and stages new files plus prior-file backups in a private `.ciphervault-restore` directory. A durable journal precedes publication. A per-target lock serializes cooperating restores; each file replacement is atomic. Failure rolls back prior publications. A subsequent restore or library `recover_interrupted_restore` rolls back an uncommitted journal, or cleans up a committed one. If another writer changes a destination, rollback stops and retains the journal rather than overwrite that edit; reconcile it before retrying. Empty created directories may remain after rollback.

This provides recovery from interrupted publication, **not simultaneous atomic visibility of an entire directory tree**. Noncooperating readers can observe intermediate files. Restore uses merge semantics: unrelated destination files remain, and historical deletion tombstones do not delete unrelated current files. Published plaintext and backups receive restrictive file permissions (Unix `0600`; Windows protected owner DACL); stage directories are private. Plaintext is intentionally present on disk during restore.

`ciphervault restore --snapshot <id> --to <directory> --dry-run` verifies snapshot data and previews create/replace/unchanged actions without creating the target, lock, journal or plaintext files. Restore, diff and legacy snapshot `run` verify recorded signing authority and load each snapshot's recorded epoch, preserving access to historical data after rekeying.

## Watcher

Native notifications feed a bounded 128-event queue and a one-job capture queue. Bursts coalesce; overflow requests a rescan. A three-second fallback scan detects missed native events. The hash baseline comes from the committed manifest and advances using captured bytes only after the local head is saved. Detection alone never acknowledges bytes; a failed capture stays dirty for later retry. Dry-run acknowledges only its in-memory inspection baseline and writes no snapshot/counter/activity state.

Hashing, capture and replication run in a dedicated worker. Upload cancellation keeps a locally committed pending upload durable; shutdown can cancel a stalled async request. Synchronous disk operations can still delay shutdown on a slow filesystem. Upload retries use each snapshot's retained signed head and original immutable recovery inventory, including the exact sealed envelope bytes. A local commit is not a remote durability guarantee; inspect replication status and rehearse recovery.

## Local keys and recovery authority

Windows local device/epoch keys use user-bound DPAPI. On other platforms, an authenticated envelope uses `CIPHERVAULT_MASTER_KEY` or a persistent private 32-byte file at `CIPHERVAULT_KEYSTORE_PATH` (default `$HOME/.config/ciphervault/keystore.key`). Provisioning publishes a fully written key exclusively; concurrent creators converge on one key, and malformed, unreadable or existing files are never replaced. Protect and back up that file separately from the vault. This is not macOS Keychain, a Linux credential service or TPM binding.

Recovery kits validate their checksum and derived public descriptors. Guardian reconstruction validates bounds, share descriptors and reconstructed authority, rejecting inconsistent combinations. Recovery authenticates device certificates against the offline recovery root and selects a unique maximal head in the certified snapshot DAG. Counters order one device; they are not a global multi-device clock. Concurrent incomparable certified heads require explicit fork resolution. Head discovery cannot prove freshness when every operator withholds newer history; an independently trusted checkpoint or offline expectation is needed for rollback detection.

Software and hardware capture prevalidate certified signing authority before advancing local state. Hardware recovery inventories use the same certified token key to sign their epoch envelopes. Simulator regressions verify protocol composition; they do not establish physical token availability or touch behavior on every platform. See [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md).

## Operator authentication and pins

Operators default to strict authentication and require enrollment. Strict startup requires a nonempty `CIPHERVAULT_OPERATOR_SERVICE_TOKEN`. Administrative enrollment is `POST /v1/identities` with `X-CipherVault-Service-Token`; its body includes `vault_id_hex`, `public_key_hex`, permissions, and optional paired account/device binding. Obtain signing keys through an independent trusted channel, then configure the client with `.ciphervault/operator_pins.json` (endpoint-to-64-hex-key JSON map) or `CIPHERVAULT_OPERATOR_PINS=endpoint=64hex,endpoint=64hex`.

If pins are configured, missing/malformed entries and key mismatches fail closed. An operator's self-signed identity response alone is not independent authentication when no pin exists. Deploy with complete pins and protected transport. The shared client sends the privileged service token only to exact endpoints listed in `CIPHERVAULT_OPERATOR_SERVICE_TOKEN_ENDPOINTS`; ordinary snapshot sessions should not receive fleet administration credentials. Compatibility flags `CIPHERVAULT_OPERATOR_STRICT_AUTH=false` and `CIPHERVAULT_OPERATOR_REQUIRE_ENROLLMENT=false` explicitly enable legacy behavior and should be confined to isolated migration/tests.

Quorum counts distinct verified signing keys. Verification proves current possession of stored ciphertext, not future availability, economic independence or ownership across operators. Keep off-network recovery material, multiple failure domains and restore drills.

`ciphervault audit --recovery-drill --operator-pin <endpoint>=<64hex>` additionally fetches the current certified head's record, manifest, unique chunks and bootstrap objects from authenticated pinned operators, checks CID/discovery/authority/closure bindings, and decrypts all files in zeroizing memory using the locally retained historical epoch key. It prints verified file/byte/object counts, writes no plaintext and opens the vault read-only. Complete configured pins can replace repeated `--operator-pin` arguments. Missing pins, corrupt/unavailable objects, missing discovery and failed plaintext integrity abort the drill; local cached ciphertext is never a fallback. The drill limits padded plaintext to 1 GiB and encrypted manifest to 16 MiB. It checks reconstruction of the locally expected head; it does not establish quorum, remote freshness or clean-machine recovery without local keys. Ordinary `audit` checks ciphertext availability only; `recover` with offline material remains the clean-machine exercise.

## Account second-factor policy

[Enforced MFA](ENFORCED_MFA.md) adds an owner-controlled durable policy, fresh
device/passkey plus session-bound one-time TOTP proof, factor/source revalidation
for scoped credentials, and explicit recovery. Existing accounts remain optional
until enrolled and enabled; upgrades do not silently change their policy.
Handoffs lose factor proof. The recovery-code sheet remains full-account recovery
authority, not independent multi-party approval. The dated deployment ledger
describes production before these working changes.

## Scoped execution

Scoped `run` resolves project/environment grants using the account endpoint and scope token. It lists metadata, then obtains requested values in one authorized batch at `POST /v1/projects/{project}/environments/{environment}/materialize`. It supports at most 100 requested secrets and 128 KiB total values. Missing/duplicate/unexpected names, full possibly partial metadata pages and revision mismatches abort before starting the child. `--revision <64hex>` pins the expected batch revision. `--dry-run` obtains metadata only; no values are materialized. Legacy snapshot execution remains available with `--legacy`.

CipherVault avoids writing injected values to plaintext files. Child processes, inherited environment, OS process inspection, swap and crash dumps remain separate exposure paths. `--no-inherit` reduces inherited variables; it is not a process sandbox.

## Open assurance and deployment work

Independent review of the v2 deterministic construction, legacy custom Blake2b KDF, sealed envelopes, hardware signing and recovery rollback/fork rules remains required. Test results and standard primitives are not a formal proof. Portable credential-service integration, physical hardware platform validation, independent freshness/checkpoint expectations, deployment-specific TLS/pin ceremonies and production load/recovery evidence must be completed for the intended deployment. The writer gate preserves compatibility while that review remains open; it does not remove the v1 privacy limitation by default.

## Deployment and capacity additions

See [account backup and recovery](ACCOUNT_BACKUP_AND_RECOVERY.md) for protected consistent backups and isolated restore verification. The GCP bootstrap accepts validated versioned local KEK keyrings while retaining legacy hex support. Keep historical key material separately.

Private dashboard telemetry shares bounded samplers per immutable vault/operator context, retains only the latest sample, closes after authorization loss and reports durable pending uploads. Hardware presence is not verified slot readiness. [HTTP response limits](../crates/storage/HTTP_RESPONSE_LIMITS.md) bound actual streamed objects/errors and discovery pages; aggregate capture memory and production capacity still require separate measurement.

HeadRecord v1 does not encode authority generation. Same-key recertification across generations can make an older head select the newest certificate and fail the later snapshot-generation check. This fails closed; general same-key renewal recovery needs a reviewed protocol/migration decision. Use independently verified recovery drills and preserve prior certificates and keys.
