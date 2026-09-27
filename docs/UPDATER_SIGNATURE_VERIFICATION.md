# Updater Signature Verification (Blocker 4)

**Status:** implementation + tests + CI wiring complete and verified.
Enforcement activates on the first release published with a
`SHA256SUMS.txt.sig` asset; that requires the one-time secret setup below.

## Problem

`ciphervault update` verified `SHA256SUMS` over GitHub TLS but never
verified who produced the checksums. A compromised release pipeline (or a
TLS endpoint serving attacker bytes) could ship arbitrary binaries with
matching checksums. Containers already had Cosign keyless signing; the
binary updater had no equivalent.

## Design (chosen)

Ed25519 detached signature over the exact `SHA256SUMS.txt` bytes, verified
against pubkeys pinned in the updater binary. This is the "cryptographically
strong, independently verifiable mechanism consistent with the repository
architecture" option: the repo already uses Ed25519 for join tickets, the
checkpoint feed, and operator identity, so no new trust infrastructure
(Rekor/Fulcio availability, OIDC) was introduced into the update path.

Full Sigstore/Cosign verification inside the updater was considered and
declined: it needs network trust-root fetches at update time and a large
new dependency closure for a client that must also update offline-cached
releases. Container images keep their existing Cosign keyless signatures;
the two mechanisms are complementary, not substitutes.

## Trust model

| Element | Value |
|---|---|
| Trusted issuer | CipherVault release engineering (offline seed holder) |
| Trusted identity | Release key id `b625994c0c3f53a6` (first 16 hex of pubkey) |
| Trust root | Pinned pubkey in `apps/cli/src/commands/update.rs` (`RELEASE_SIGNING_KEYS`): `b625994c…22c1e` (full value in code) |
| Artifact identity | Exact `SHA256SUMS.txt` bytes of release tag T |
| Signature format | `CIPHERVAULT-RELEASE-SIG-V1` 4-line envelope (`tag`, `key-id`, `signature`; lowercase-canonical hex) |
| Signed message | Raw `SHA256SUMS.txt` bytes |
| Replay/version protection | Envelope binds the release tag; a signature cut from any other tag is rejected. Archive names inside the sums additionally bind the tag. Downgrades are refused by the existing version comparison. |
| Key-based vs keyless | Key-based (offline seed). No Dritten network trust lookups at install time. |
| Failure behavior | Fail closed: missing/invalid/untrusted signature aborts before checksum, extract, and install. SHA-256 verification is kept and runs after signature verification. |

## Verification pipeline

`Artifact → Signature Verification → Integrity Verification → Trust Policy → Install`

1. Download archive + `SHA256SUMS.txt` + `SHA256SUMS.txt.sig` (all required assets of the release).
2. `verify_release_signature`: envelope shape → version → tag binding → key-id is pinned → Ed25519 `verify_strict` over the sums bytes.
3. `find_checksum`: the sums must name the exact archive under install; `SHA256` of the downloaded bytes must match.
4. Existing archive-confinement checks (no symlinks, no traversal, unique binaries), then install.

## Key management and rotation

- The seed lives in the GitHub Actions secret `CIPHERVAULT_RELEASE_SIGNING_KEY`
  (64 lowercase hex) plus an offline copy with the fleet seed. It never
  enters the repo, logs, or chat.
- Signing refuses seeds whose pubkey is not pinned (`release sign` fails
  before emitting anything), so a ceremony with the wrong key fails at
  signing time, not at users' updaters.
- Rotation: append the successor `(key-id, pubkey)` to
  `RELEASE_SIGNING_KEYS` and ship it BEFORE the successor signs anything;
  remove the predecessor only after every supported updater carries the
  successor. No envelope change is needed.

## CI / release wiring

- `.github/workflows/release.yml`, `publish-release` job, new `Sign SHA256
  Checksums` step: fails closed when the secret is missing; the freshly
  built Linux CLI self-signs (`release sign`) and self-verifies
  (`release verify`) before `Create GitHub Release` uploads
  `dist-release/*` (the `.sig` rides along automatically).
- Transition: updaters older than this change ignore the extra asset;
  updaters with this change require it. The release that introduces
  enforcement must itself be signed (guaranteed by the workflow above).
- Manual publishes (`scripts/publish_release_assets.ps1`): sign with
  `ciphervault release sign --tag <tag> --sums SHA256SUMS.txt` and upload
  the `.sig`; unsigned manual releases are rejected by new updaters.

## Tests (all executed 2026-09-26, `cargo test -p ciphervault-cli --bin ciphervault`: 136 passed, 0 failed)

Positive:

- `genuine_release_signature_verifies` — offline-generated signature from
  the real pinned seed over fixture sums verifies (seed never in repo;
  only the resulting signature is embedded).
- `signature_then_checksum_order_pins_artifact_identity` — verified sums
  still name the exact archive; other tags absent.

Negative (each asserts the precise failure):

- `tampered_sums_rejected`, `flipped_signature_bit_rejected`,
  `wrong_signer_rejected` (attacker key, pinned key-id claimed),
  `unknown_key_id_rejected` (self-consistent attacker envelope),
  `cross_tag_signature_rejected`, `malformed_envelopes_rejected`
  (bad version, truncation, empty/unsigned, extra line, uppercase hex,
  short signature, missing prefix).
- `unpinned_seed_refuses_to_sign`, `seed_loader_rejects_wrong_lengths`
  (ceremony side).
- `pinned_release_keys_are_valid_and_self_describing` (pin hygiene).

Gates: `cargo fmt --check` clean, `cargo clippy -p ciphervault-cli
--all-targets -- -D warnings` clean.

## Activation record (completed 2026-09-27)

1. [DONE] Release seed stored as the `CIPHERVAULT_RELEASE_SIGNING_KEY`
   repo secret (API-verified present).
2. [DONE] `v1.0.18` published with `SHA256SUMS.txt.sig` (205 B). The
   published signature was independently verified: correct envelope
   version, tag `v1.0.18`, key id `b625994c0c3f53a6`, Ed25519 valid
   over the published sums under the pinned root (`SIG-OK`). Updaters
   ≥ 1.0.18 now enforce authenticity; older updaters ignore the asset.
3. Standing rule: never publish an unsigned release; the workflow
   fails closed without the secret.

Follow-up fixed in the same session: the manifest-fill job's direct
push to `main` was rejected by repository rules (GH013: PRs required),
so the job now opens a PR instead (commit `707b3dc`); v1.0.18 hashes
were filled manually with the identical procedure and pushed as
`db18742`.

## v1.0.19: Windows extraction fix + migration note

Live reproduction (2026-09-27) proved Windows self-update never worked:
`powershell.exe` joins everything after `-Command` into one command
line, so the updater's `$args[0]`/`$args[1]` placeholders were always
empty and every update died in `Expand-Archive` ("Windows release
archive extraction failed"). Fixed in v1.0.19 by embedding quoted paths
in a single `-Command` string (`windows_expand_archive_command`, with
regression tests). Same release: `update --reinstall` (verified repair
path; proven end to end against the real v1.0.19 artifacts on Windows:
download → signature → checksum → extract → swap all green) and a TUI
fix that quits promptly after staging so the swap helper can proceed
(previously the TUI lingered, stalling the install).

Migration: Windows installs at ≤1.0.18 carry the broken updater and
cannot self-update — those users must fresh-install ≥1.0.19 once via
`dist/scripts/install.ps1` (or the release zip), after which in-app
update works. If the installer reports a locked file, a CipherVault process (TUI, agent, operator, maintenance) is running from the install directory: the installer stops only those processes automatically (reported at the end so they can be restarted), retries the copy, and fails with the holding PIDs if the lock persists. Set `CIPHERVAULT_INSTALL_NO_STOP=1` to disable the auto-stop and fail fast with manual instructions instead. v1.0.19's own signature verified independently (`SIG-OK`,
key `b625994c0c3f53a6`); v1.0.19 manifest hashes merged via PR #4 after
the fill job's branch push (repo setting still blocks Actions-created
PRs — either enable "Allow GitHub Actions to create and approve pull
requests" in repo settings, or keep opening the fill PR manually).

## Files

- `apps/cli/src/commands/update.rs` — trust roots, verification, updater hook, tests
- `apps/cli/src/commands/release.rs` — `release sign` / `release verify`
- `apps/cli/src/main.rs` — `release` subcommand wiring
- `.github/workflows/release.yml` — signing step
