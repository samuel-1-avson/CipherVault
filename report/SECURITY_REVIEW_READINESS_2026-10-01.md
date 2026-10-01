# CipherVault internal security audit — 1 October 2026

## Scope and outcome

The user chose an **internal audit** for this development cycle. This focused
source review extends the 30 September project audit; it is not an exhaustive
fresh penetration test or independent cryptographic certification. Released
baseline: v1.0.26 at `4966a5ce057b81ac0ee8795881133cad91f8c3ac`; starting checkout:
`07425272c67049f3a981a41c1f77eb7ae17269ac`. Changes described below are in the
current worktree, not a claim of a new production rollout.

The source pass covered sealed-box key agreement, v1/v2 chunk derivations and
manifest validation, authenticated recovery head selection, operator control
permissions and HTTP I/O admission, installer/deployment review entry points,
and the new account MFA design's policy/proof/revocation boundaries. Tests below
cover the crypto/operator corrections and source evidence builder. The final
integrated MFA/custody/capacity results belong in their implementation ledgers.

The audit corrected sealed-box handling of non-contributory X25519 inputs,
operator HTTP admission, and account mutations that reused authorization across
database guard changes. A new invitation acceptance regression also exposed and
corrected an existing SQL column error. No evidence of a live exploit or data
compromise was found or claimed.

## Findings and disposition

| ID | Priority | Finding | Disposition and practical limit |
|---|---|---|---|
| IA-01 | P2 | `seal_box` / `open_sealed_box` derived AEAD material from X25519 shared secrets without rejecting non-contributory inputs. A low-order recipient yields publicly derivable box encryption; a low-order ephemeral lets an attacker construct an AEAD-valid synthetic box from public values. | **Fixed and retested.** Both primitives now reject `was_contributory() == false` before KDF/AEAD. Tests include all-zero/order-one recipient points and forged ephemeral boxes. Valid wire encoding is unchanged. Authenticated recovery envelope signatures already mitigate arbitrary unauthenticated envelope substitution; this finding does not demonstrate a production recovery-root bypass. |
| IA-02 | P2 | Operator HTTP `bounded_io` used awaited semaphore acquisition: 16 running workers but no separate limit on queued operation futures. Slow disk traffic could accumulate waiting requests. | **Fixed and retested.** Immediate admission returns HTTP 503 `Operator I/O capacity exhausted; retry later` on saturation. The permit stays held through blocking completion. A regression holds all 16 workers, proves a 17th closure never runs and fails promptly, releases workers, and verifies admission recovers. Request body buffering, network admission and total process memory still require measured validation. |
| IA-03 | Existing P1 assurance/privacy limit | Default v1 exposes public candidate-file confirmation and replaces encrypted chunk identity across complete-file changes (F13/F21). | **Open for default/history.** V2 remains explicitly opt-in, with keyed identities and separate HKDF domains. Authenticated manifest/header/nonce/digest checks are present. Internal tests are not proof of deterministic construction security and do not erase historical v1 exposure. |
| IA-04 | P2 recovery reliability | HeadRecord v1 lacks authority generation. The head selector tries newest certificates first; same-key recertification can associate an older head with a newer certificate and fail the later snapshot-generation check. | **Open; fails closed.** A reviewed protocol/migration and cross-generation fixtures are needed. Do not resolve by silently accepting revoked generations. Separate trusted freshness expectations remain necessary if all operators withhold newer heads. |
| IA-05 | P2 documentation/process | Audit readiness described an earlier open-write deployment, an obsolete test count, and no internal product findings; hardware/quorum wording in older specifications exceeds verified physical-device evidence. | **Readiness document refreshed.** Current scope now covers account confidentiality, MFA, v1/v2 limits, recovery generations, permissions/pins and release trust. Physical token, independent custody and external certification claims remain qualified. |
| IA-06 | P2 authorization/revalidation | Several account credential/member mutations authenticated a session, released the DB guard, then later reacquired it for storage. A cached SessionView cannot observe intervening logout, MFA activation or member-role revocation. | **Fixed and retested in the single-service execution model.** Shared held-connection helpers re-read session, factor/policy and required role immediately before sensitive storage. WebAuthn registration/revocation, device revocation, recovery-code issuance, vault links, invitation/member changes and TOTP enrollment/revocation use them; deliberate signed bootstrap and recovery-device enrollment remain. Three regressions reproduce valid cached auth followed by revocation/policy/role changes. This does not certify multiple independent service processes sharing SQLite. |
| IA-07 | P2 functionality | Authorized invitation acceptance selected `invitations.invited_at_utc`, but that table defines `created_at_utc`; the transaction returned HTTP 500. | **Fixed and retested.** The source selection now uses `created_at_utc` while preserving membership `invited_at_utc`. Router regression rejects TOTP-only/recovery sessions and missing target-policy factor proof without consuming the invitation, then confirms acceptance succeeds with current primary/factor proof. |
| IA-08 | P2 recovery resource bounds | The new custody tool enumerated tar members before checking member count/size and captured complete native/cloud listing output before checking a byte limit. | **Fixed and retested before promotion.** Fixed USTAR header parsing rejects extra/extended/oversized entries before body processing, caps aggregate expanded bytes and padding, and native stdout capture terminates on 1 MiB overflow. Real child-process output/timeout cases and adversarial compressed-archive fixtures pass. Other archive formats require a separately reviewed adapter. |
| IA-09 | P2 replication compatibility | Integration testing showed immediate operator admission 503s could cause content-addressed uploads to fail quorum without a retry. | **Fixed and retested.** Immutable object PUT retries only HTTP 503, with at most three identical-body attempts and 100/200 ms backoff. Permanent failures remain immediate; lease and recovery append writes retain their existing behavior. TCP regressions cover eventual success, fixed exhaustion, unchanged bytes/auth/path and non-retryable denial; concurrent replication and partial-log healing pass. |

## MFA cross-check disposition

The new design binds factor proof to the authenticated session, stores a random
proof ID plus verification time and active-TOTP ciphertext fingerprint, and
binds issued scoped credentials to that proof. Factor replacement/revocation,
session logout, policy changes and proof refresh must invalidate affected
credentials. Handoffs must receive no inherited factor attestation.

The review raised these integration checks to the implementation owner. The
following dispositions describe tested worktree behavior, not deployed policy.

| Review check | Disposition and evidence |
|---|---|
| Recheck rate limits inside the same immediate transaction used for TOTP/recovery verification. | **Implemented and retested.** MFA step-up and emergency reset check under their transaction. Concurrent guesses across two account connections yielded exactly five unauthorized attempts and eleven rate-limited attempts in the regression. |
| Re-read the session, target policy and role with the final storage connection. | **Implemented and retested for reviewed sensitive mutations.** IA-06's three intervening-state regressions reject logout, newly required MFA and revoked membership; signed bootstrap/recovery enrollment remains deliberate. |
| Cover target-account MFA for membership operations, with current primary/factor proof. | **Implemented and retested.** The invitation router test rejects weak sessions and missing target-policy proof without consuming the invitation, then accepts current proof. It also exposed IA-07's SQL defect, now fixed. |
| Prevent old credentials from inheriting a later step-up, and revalidate the signed proof ID and expiry. | **Implemented and retested.** The scoped-origin test rejects missing proof, five-minute expiry, refreshed proof IDs and replaced TOTP ciphertext; handoff tests show no inherited factor attestation. |
| Emergency reset consumes an unused code and revokes factor/sessions/handoffs atomically, without MFA attestation. | **Implemented and retested.** The reset regression rejects recovery-only sessions, invalidates sessions and factor, and rejects consumed-code reuse. The added end-to-end test proves the documented replacement-device/two-code exception and verifies both codes consumed, required policy disabled, factor revoked and every account session revoked. |

The implementation owner explicitly accepts the existing full-account recovery
exception: one recovery code can establish a restricted recovery session and
authorize enrollment of a replacement device when prior keys are lost. After
that device proves its key, a **second distinct unused recovery code** can reset
MFA. This preserves lost-key recovery. Two codes from one sheet are not two
independent factors; the recovery-code sheet is full-account recovery material
and requires protected custody. A recovery session alone must not reveal scoped
secrets, mint credentials or change MFA policy. Reset revokes all sessions and
the factor and requires fresh login/enrollment; it is not MFA attestation.

The account library run passed the new storage-boundary and invitation
regressions plus the implementation owner's MFA suite. The subsequently added
full recovery exception regression also passed on its own. Operational policy
activation and the complete release/CI gates remain separate from those local
results. Existing released TOTP alternate login alone is not enforced MFA.

## Focused verification completed

| Check | Result |
|---|---|
| `cargo test -p ciphervault-crypto --locked` | **37 passed, 0 failed:** 33 unit and 4 integration tests, including both new low-order regressions; 0 ignored. |
| `cargo test -p ciphervault-operator --locked --lib --bins` | **86 passed, 0 failed:** 82 library and 4 binary tests; 0 ignored. Covers HTTP admission saturation/recovery and typed loopback binding. |
| `cargo test -p ciphervault-account --locked --lib` | **154 passed, 0 failed, 1 existing ignored** after final storage-guard changes and invitation fix. Includes the three intervening-revocation/policy/role regressions and router invitation factor-policy/acceptance case. |
| `cargo test -p ciphervault-account --locked --lib mfa::tests::full_account_recovery_requires_new_device_proof_and_two_distinct_unused_codes` | **1 passed, 0 failed, 155 filtered.** A real replacement-device enrollment/login follows restricted redemption; recovery-only step-up/reset/mint and consumed-code reset are denied. Second-code reset disables policy, revokes the factor and invalidates every account session. |
| Rustfmt on changed crypto/operator files | Passed. |
| `node tests/release_installer_signatures.cjs` | **14 passed, 0 failed:** independent bootstrap signature cases retested during this internal review. |
| `python -m unittest discover -s scripts/security -p test_review_pack.py` | **7 passed, 1 skipped, 0 failed** at preparation: Windows symlink creation lacked privilege; an actual Windows junction/reparse-parent rejection passed. Tests cover tracked-runtime exclusion, frozen-ref selection, repeatability/no overwrite, hash tampering, membership, traversal and duplicates. |
| `git diff --check` | Passed at preparation; repository CRLF normalization notices are informational. |

The [isolated TCP capacity result](capacity-http-admission-2026-10-01.json)
also exercises the operator admission behavior with strict authentication on a
Windows debug build. At 64 concurrent mixed 64 KiB operations, it recorded 227
successes and 13 capacity 503s, with no unexpected failures. A burst of 128
concurrent 1 MiB writes recorded 20 successes and 108 capacity 503s; all stored
objects passed CID readback checks. These are short local overload observations,
not sustained release-build production throughput limits.

Operator `--bind-address <IP>` supports isolated HTTP drills on `127.0.0.1` or
`::1`, with typed IP parsing. Default remains `0.0.0.0`; P2P listeners have
separate settings. Use the capacity harness's real workload results before
setting supported throughput/concurrency claims.

## Evidence integrity and remaining limits

The [source pack builder](../scripts/security/build_review_pack.py) exports
explicitly allowed tracked source/test/configuration files and curated review
documents. It produces deterministic ZIP metadata and a SHA-256 manifest,
records the commit/tree and worktree/frozen-reference status, never uploads,
never overwrites existing output, and reads verification without extraction.
Runtime `.ciphervault`, `.agents`, key/environment/database/recovery/archive
files and ambient logs are excluded. Synthetic vectors in source remain.

Inspect the manifest and perform the repository secret scan before sharing.
Integrity hashes are not authenticity; a separately authenticated archive digest
is required for transfer to an independent reviewer. Worktree source can change
between reads; regenerate from the exact final commit after integrated checks.

The internal audit leaves **independent assurance absent**. No reviewer was
appointed, contacted or paid. Full physical-device ceremonies, clean-machine
recovery with independently held keys, actual custodial acknowledgments,
production capacity certification, and v2 default promotion remain separately
gated by evidence. The current work does not itself establish those outcomes.

See [updated audit readiness](../docs/SECURITY_AUDIT_READINESS.md) for complete
scope, adversarial cases, remaining risks, reproducible checks and closure
requirements; see the [project reassessment](PROJECT_REASSESSMENT_2026-10-01.md)
for the prior overall rating and broader roadmap.
