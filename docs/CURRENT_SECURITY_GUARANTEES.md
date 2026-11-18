# Current security and operational guarantees

Updated 18 November 2026 (v1.0.35). Sections added or revised since v1.0.31 cover chunk v2 as the default writer, agent-safety surfaces, non-Windows key custody and HeadRecord v2. This describes the working implementation, not independent cryptographic certification or a claim that unpromoted changes run in production. Run current checks and review their actual results before release.

## What changed in v1.0.31

- **Agent-bridge scrubbing is exact:** `ciphervault run --json` scrubs captured output against the injected values themselves (raw, percent-encoded, base64) before returning it; every vault-sourced value is treated as secret. `ciphervault redact` exposes the same exact+shape redaction as a stdin filter, and `ciphervault export-env` (machine consumers only) refuses to write to a terminal.
- **Private commitment transactions (opt-in):** `CIPHERVAULT_ANCHOR_TX_VERSION=2` anchors with only the commitment + a per-anchor vault pseudonym on-chain; salt/head stay in local checkpoint evidence. Default remains v1 (plaintext salt/head) until v1.0.31+ validators are deployed; both forms validate.
- **Anchor quorum honesty:** with a multi-validator set the CLI publishes the proposal first and reports `PROPOSED — awaiting fleet quorum` instead of committing a local fork; solo mode is labeled as such.
- **Signed dedup proofs:** the pre-upload dedup challenge now verifies the operator's signed PoS receipt, not just a proof hash.
- **Threshold-aware recovery:** `combine_shares_with_threshold` rejects below-threshold share sets in the guardian path; new recovery kits add a SHA-256 checksum alongside the legacy CRC32 (old kits still load).
- **Operator defaults tightened:** HTTP API binds loopback unless `0.0.0.0` is explicit; service tokens under 32 chars refuse startup (temporary override `CIPHERVAULT_OPERATOR_ALLOW_SHORT_TOKEN=1`).

Stated limits, plainly: the operator challenge ("Proof-of-Storage") proves an operator can produce the object at challenge time — it is a possession/readback check, not a proof of storage over time. The account plane is **single-writer SQLite** (LiteFS optional); the documented PostgreSQL topology is not implemented and fails closed. CipherChain liveness under split votes needs operator coordination (see ADR-013); gossip state is capped, and proposal vetting is O(log n) in history.

## Agent-safety surfaces (v1.0.32 to v1.0.35)

These controls keep secret values out of an AI agent's context and leave a verifiable record of what the agent touched. They apply to `ciphervault run`, `redact`, `hook agent-pre` / `agent-post`, `ciphervault mcp`, `agent-log`, `env-doctor` and the Hermes plugin ([README](../plugins/ciphervault/README.md)). They are not a defense against a malicious process running as the same OS user, and they do not constrain what an approved child process does with secrets it was given.

**Exact-value scrubbing.** `run --json`, `redact`, the stdio bridge, `hook agent-post` and the plugin's result scrubber match every vault-sourced value in raw, percent-encoded, base64, base64url, hex and JSON-escaped forms, every PEM private-key block (including a dump of body lines without headers), and common credential shapes. `redact --json` reports `exact_values_complete`; if any tracked working copy could not be loaded, callers must treat the output as incomplete and the plugin withholds it. Stated limits: values shorter than 6 characters are not exact-matched, and a child that transforms a secret in some other way (splitting, reversing, encrypting) before printing can evade matching. That is the reason `--no-net` and `--proxy` exist.

**Least privilege and network control.** `run --allow-keys` injects only the named variables. `run --no-net` runs the child without network access using Linux `unshare`, macOS `sandbox-exec` or a Windows AppContainer, and refuses to run when none is available. It is a network sandbox, not a general process sandbox. On Windows, programs that need files outside the sandbox's readable locations (for example third-party Python packages) can fail to start. `run --proxy` keeps real API keys in a loopback credential proxy in the parent process, so they never enter the child's environment. The child can still *use* the proxy to make authenticated requests to the pinned upstreams, so it limits exposure of the key, not use of it. `--proxy` and `--no-net` cannot be combined.

**Workspace policy.** `.ciphervault/policy.toml` defines `[vault]` (`sealed_mode`, `default_no_net`) and `[profiles.NAME]` (`commands`, `allow_keys`, `no_net`, `proxy`, `upstreams`). `run --profile` enforces the profile's command allowlist and merges its `allow_keys`; unknown keys are rejected. The file is plain text protected only by filesystem permissions (it is not signed). The Hermes leak guard blocks agent edits to it.

**Sealed working tree.** `push --shred` (alias `--seal`), or `sealed_mode = true`, zero-fills and removes tracked plaintext from the working directory after the snapshot is sealed. This is best-effort: journaling or copy-on-write filesystems, SSD wear levelling, cloud-synced folders and backups can retain earlier copies of the plaintext.

**Agent audit log.** `ciphervault agent-log` stores hash-chained entries signed by the device key under the domain `CipherVault-AgentAudit-v1`. Entries hold tool, path, decision, counts and hashes, never contents. Writes from callers carry an HMAC under a per-vault `audit_hmac.key`. Scrubbed results record the SHA-256 of the exact output the model received, so `agent-log check` can show whether an output passed the scrubber. Any mid-chain edit, deletion or reorder is detected. Tail truncation is detected only against the fleet-anchored checkpoint (`agent-log verify-remote`), which a replicated push and a plugin run-approval request send to your operators (entry count and head hash only). An attacker who can sign as the device on the same machine can re-forge and re-anchor the chain; hardware-token signing mitigates this.

**Local dashboard.** `ciphervault ui --local` requires a startup bootstrap token or an existing private session before `/api/context` issues a session cookie.

**Agent hosts.** The Hermes plugin routes every `ciphervault_run` through Hermes' human-approval gate; "always" grants cover only the same execution envelope (program, profile, inline-code hash, network mode, `allow_keys`). Where a vault is present its result scrubber fails closed, scanning up to 4 MB per result and truncating beyond that instead of passing text unscanned. The plugin's only network use is the `bootstrap` download (checked against SHA-256 pins in its source) and the audit-head checkpoint. `ciphervault mcp` exposes seven tools, defaults `run` to `--no-net` where supported, and never forwards an agent-supplied `proxy_upstream`. Hook-based guards cover only tool calls that pass through the agent host's hooks.

**Verification status.** Windows is the verified platform. The Linux and macOS code paths for `--no-net`, key custody and smartcards are implemented but have not yet been run on real hosts, and hosted CI is currently paused; see [PLATFORM_SUPPORT.md](PLATFORM_SUPPORT.md). The plugin and these surfaces have had internal review only.

## Chunk versions and deployment gate

The default writer is **chunk protocol v2**. Set `CIPHERVAULT_CHUNK_V2_WRITE=0` to force legacy v1 captures. Unset or `1` selects protocol v2; empty, other or non-Unicode values fail capture before file processing. Library callers can pass `ChunkWriteVersion` explicitly to `create_snapshot_with_write_version` or `create_snapshot_with_signer_and_write_version`, avoiding process environment changes. Readers accept v1 and v2 independently of this gate and reject unknown chunk versions. Recovery records, certificates and encrypted manifests retain protocol version 1.

V1 preserves historical IDs, KDFs and ciphertext addresses. Its public complete-file identifier permits an operator to confirm a candidate file using public vault/epoch fields. V1 also binds chunk encryption to the whole file version, preventing encrypted reuse across edits. These limitations apply to v1 objects (written only under the explicit opt-out since v2 became the default) and to existing remote history; enabling v2 does not rewrite old objects.

Chunk protocol v2 (the default writer) uses HKDF-SHA256 for keyed opaque file/chunk identifiers and separately derived chunk keys/nonces, with explicit version, domain, vault, epoch and identifier bindings. Unchanged padded chunk content has the same ciphertext CID within one vault and epoch, including chunks shifted by an insertion or repeated in one file. Cross-vault and cross-epoch reuse is deliberately excluded. Content-defined boundaries can change around an edit; no fixed deduplication percentage is promised. Small files receive a 4 KiB padding floor. The encrypted manifest authenticates file order, raw/padded lengths and the whole-file digest.

Operators without epoch keys cannot compute v2 opaque IDs from public candidate hashes. They still observe chunk equality within an epoch, ciphertext lengths, object counts, vault/epoch identifiers, traffic and access patterns. Compromised keys or an encryption oracle can restore candidate-confirmation ability. Deterministic encryption is therefore not a claim of semantic security without equality leakage. Exact derivations and compatibility boundaries are in [CHUNK_PROTOCOL_V2.md](../crates/snapshot/CHUNK_PROTOCOL_V2.md).

## Capture and restore

Capture rejects traversal, linked/reparse-point paths, nonregular files and files above 256 MiB before unbounded allocation. It bounds reads, checks opened-handle and pathname metadata before/after, and hashes the bytes actually captured. This detects ordinary concurrent edits; metadata checks are not an OS transaction or a defense against a privileged attacker deliberately restoring metadata and racing ancestor replacement.

Restore decrypts and verifies every file before publication, preflights destinations, and stages new files plus prior-file backups in a private `.ciphervault-restore` directory. A durable journal precedes publication. A per-target lock serializes cooperating restores; each file replacement is atomic. Failure rolls back prior publications. A subsequent restore or library `recover_interrupted_restore` rolls back an uncommitted journal, or cleans up a committed one. If another writer changes a destination, rollback stops and retains the journal rather than overwrite that edit; reconcile it before retrying. Empty created directories may remain after rollback.

This provides recovery from interrupted publication, **not simultaneous atomic visibility of an entire directory tree**. Noncooperating readers can observe intermediate files. Restore uses merge semantics: unrelated destination files remain, and historical deletion tombstones do not delete unrelated current files. Published plaintext and backups receive restrictive file permissions (Unix `0600`; Windows protected owner DACL); stage directories are private. Plaintext is intentionally present on disk during restore.

`ciphervault restore --snapshot <id> --to <directory> --dry-run` verifies snapshot data and previews create/replace/unchanged actions without creating the target, lock, journal or plaintext files. Restore, diff and legacy snapshot `run` verify recorded signing authority and load each snapshot's recorded epoch, preserving access to historical data after rekeying.

## Watcher

Native notifications feed a bounded 128-event queue and a one-job capture queue. Bursts coalesce; overflow requests a rescan. A three-second fallback scan detects missed native events. The hash baseline comes from the committed manifest and advances using captured bytes only after the local head is saved. Detection alone never acknowledges bytes; a failed capture stays dirty for later retry. Dry-run acknowledges only its in-memory inspection baseline and writes no snapshot/counter/activity state.

Hashing, capture and replication run in a dedicated worker. Upload cancellation keeps a locally committed pending upload durable; shutdown can cancel a stalled async request. Synchronous disk operations can still delay shutdown on a slow filesystem. Upload retries use each snapshot's retained signed head and original immutable recovery inventory, including the exact sealed envelope bytes. A local commit is not a remote durability guarantee; inspect replication status and rehearse recovery. Dry-run inspection persists nothing to disk; it advances only the watcher instance's in-memory baseline, and a dry-run instance never performs real captures (`dry_run` is fixed at construction).

## Local keys and recovery authority

Windows local device/epoch keys use user-bound DPAPI. On other platforms, the same authenticated envelope is keyed in this order: an explicit `CIPHERVAULT_MASTER_KEY` or `CIPHERVAULT_KEYSTORE_PATH` override; otherwise a key held in the OS credential store (macOS Keychain through `/usr/bin/security`, Linux Secret Service through `secret-tool`); otherwise an already-provisioned private 32-byte file (default `$HOME/.config/ciphervault/keystore.key`). A fresh install provisions a credential-store key when it can. With no usable credential store the CLI falls back to the file keystore unless `CIPHERVAULT_REQUIRE_OS_KEYRING=1` is set, in which case it fails instead. File provisioning publishes a fully written key exclusively; concurrent creators converge on one key, and malformed, unreadable or existing files are never replaced. The credential-store paths are implemented but have not yet been exercised on real macOS or Linux hosts, so confirm which backend is active (`ciphervault doctor`) and protect and back up the key file separately from the vault. The file keystore is not TPM binding.

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

CipherVault avoids writing injected values to plaintext files. Child processes, inherited environment, OS process inspection, swap and crash dumps remain separate exposure paths. `--no-inherit` reduces inherited variables; it is not a process sandbox. `--allow-keys` and `--no-net` narrow what the child receives and can reach; see [Agent-safety surfaces](#agent-safety-surfaces-v1032-to-v1035).

## Open assurance and deployment work

Independent review of the v2 deterministic construction, legacy custom Blake2b KDF, sealed envelopes, hardware signing and recovery rollback/fork rules remains required. Test results and standard primitives are not a formal proof. Portable credential-service integration, physical hardware platform validation, independent freshness/checkpoint expectations, deployment-specific TLS/pin ceremonies and production load/recovery evidence must be completed for the intended deployment. Chunk v2 is the default writer while that review remains open; v1 objects and history written before the default changed keep their privacy limitation, and `CIPHERVAULT_CHUNK_V2_WRITE=0` still writes v1. External review of the agent-safety surfaces and the Hermes plugin is also outstanding.

## Deployment and capacity additions

See [account backup and recovery](ACCOUNT_BACKUP_AND_RECOVERY.md) for protected consistent backups and isolated restore verification. The GCP bootstrap accepts validated versioned local KEK keyrings while retaining legacy hex support. Keep historical key material separately.

Private dashboard telemetry shares bounded samplers per immutable vault/operator context, retains only the latest sample, closes after authorization loss and reports durable pending uploads. Hardware presence is not verified slot readiness. [HTTP response limits](../crates/storage/HTTP_RESPONSE_LIMITS.md) bound actual streamed objects/errors and discovery pages; aggregate capture memory and production capacity still require separate measurement.

HeadRecord v2 records the signing authority generation, and recovery matches a head only to a certificate of that generation. Heads written as HeadRecord v1 do not encode it. For those, same-key recertification across generations can make an older head select the newest certificate and fail the later snapshot-generation check. This fails closed; general same-key renewal recovery needs a reviewed protocol/migration decision. Use independently verified recovery drills and preserve prior certificates and keys.
