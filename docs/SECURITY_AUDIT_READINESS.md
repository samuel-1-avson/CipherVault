# Internal security audit and review readiness

Updated **1 October 2026**. This package supports the internal audit chosen for
the current improvement cycle and preserves an exact handoff for any future
independent review. An internal source review, including another AI agent's
cross-check, does not establish independent certification. No external reviewer
has been assigned and no completed external audit is claimed.

## Reference and evidence

Released baseline: **v1.0.26**, commit
`4966a5ce057b81ac0ee8795881133cad91f8c3ac`. The documentation checkout at the start
of this cycle was `07425272c67049f3a981a41c1f77eb7ae17269ac`. New MFA, custody, and
capacity changes must be reviewed as a separate delta. Freeze their final commit
after validation; an evolving worktree is not an audited immutable release.

The [dated internal assessment](../report/SECURITY_REVIEW_READINESS_2026-10-01.md)
records findings and focused retests. The [current guarantees](CURRENT_SECURITY_GUARANTEES.md),
[original audit](../report/PROJECT_AUDIT_2026-09-30.md),
[remediation ledger](../report/AUDIT_REMEDIATION_2026-09-30.md), and
[deployment ledger](../report/DEPLOYMENT_2026-09-30.md) provide the broader history.
The old statements that the fleet remained open-write and that no internally
discovered product findings existed are superseded by that remediation and
deployment evidence.

## Confidentiality models and boundaries

Client vault files are encrypted locally before upload to operators. Operators
still observe lengths, equality, counts, vault/epoch labels and traffic. Default
v1 additionally permits public candidate-file confirmation; opt-in v2 changes
identifiers/keying but does not erase old v1 history or remove all leakage.

The hosted account service is a separate confidentiality model: it decrypts
authorized account secrets using service-accessible KEKs. Compromise of that
runtime or its keys can expose account plaintext. It is not universally
zero-knowledge.

Audit these boundaries explicitly:

1. Offline recovery root/device authority to capture, historical epochs,
   restore, guardian reconstruction and remote discovery.
2. Human signing-key/passkey sessions, alternate TOTP/recovery login, enforced
   second-factor policy, scope credentials, memberships and administration.
3. Browser cookies/dashboard proxy to account API and immutable vault/project
   context, including origin/CSRF, redirects and credential forwarding.
4. Vault storage sessions to fleet administration, HTTP/P2P equivalence,
   service-token endpoint allowlists and independently obtained pins.
5. Certified recovery objects and distinct signer quorum to freshness,
   failure-domain independence and actual recoverability.
6. CI signing keys/tag-bound manifests to installers/updater; GitHub OIDC signer
   identity and exact signed image digests to bootstrap/rollback.
7. Consistent account backups to separately retained keys, authenticated custody
   receipts, isolated restore, and restored-session invalidation.

## Source scope and adversarial questions

| Area | Entry points | Required checks |
|---|---|---|
| Cryptography | `crates/crypto/src`, `crates/format/src`, `crates/snapshot/src`, [v2 specification](../crates/snapshot/CHUNK_PROTOCOL_V2.md), [crypto specification](CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md) | Custom Blake2b KDF/domain separation, HKDF bindings, deterministic nonce/collision assumptions, candidate confirmation and equality leakage, malformed versions/AEAD, authenticated order/length, repeated/shifted chunks, cross-vault/epoch isolation, non-contributory X25519 inputs. |
| Recovery and restore | `crates/recovery/src/trust.rs`, recovery/format/snapshot/local-store crates, CLI `recover`, `restore`, `rekey`, `audit` | Root/certificate/envelope binding, same-key authority renewal, stale/all-withheld history, incomparable heads, cycles/conflicts, large logs, guardian mixing, hardware/software composition, interrupted publication and external destination edits. |
| Account policy | `services/account/src/{http,sessions,webauthn,totp,mfa,guards,policy,scope_tokens,secret_routes,memberships,devices,recovery}.rs` | Origin/cookie checks, one-use challenges, strong/recovery session boundaries, durable policy, session-bound second factor, expiry/replay/re-enrollment/revocation, handoffs, emergency reset, narrowed tokens/admin/move/export, branch claims and dual control. |
| Account encryption/recovery | `services/account/src/{secrets,disaster_recovery,state,scoped}.rs`, [backup procedure](ACCOUNT_BACKUP_AND_RECOVERY.md) | Historical/immutable KEKs, bounded DEK rewrap, held-transaction materialization/revision and authorization checks, backup consistency, wrong/missing keys, authenticity versus checksum, isolated restore, independent custody. |
| Operators/storage | `services/operator/src/{handlers,state,main,swarm}`, `crates/storage/src`, integration tests | Permission bits, persisted account/device revocation, strict startup/enrollment, endpoint pins/redirects, ownership/quota conservation, renewal, durable recovery append/pagination, unique signing keys, HTTP/P2P consistency, saturation/admission and restarts. |
| Interfaces/local files | `apps/cli/src/dashboard`, `apps/ui`, scoped run and OS keystore | Cross-workspace isolation, browser origin/CSP, streaming revocation, plaintext/environment exposure, control-token inheritance, linked/reparse paths, bounded/concurrent capture, private restore files. |
| Distribution | `.github/workflows`, updater/release commands, `dist/scripts`, `tests/release_installer_signatures.cjs`, `deploy`, `scripts/gcp` | Independent release pin, signed exact-tag sums, old bootstrap compatibility, archive contents, substitution/rollback attacks, least-privilege runtime, exact signer/issuer/digest verification and secret-safe logs. |
| Anchoring/evidence | `contracts`, `crates/storage/src/chain.rs`, feed/finality commands | Chain/domain replay, publisher pins, equivocation, finality/reorg and freshness assumptions. Testnet anchoring is not mainnet settlement assurance. |

## Current unresolved assurance boundaries

- **Default v1 privacy/dedup limits:** F13/F21 remain for default captures and
  historical objects. Keep v2 opt-in; review its deterministic construction and
  reader/migration behavior before changing default writes.
- **Authority renewal:** HeadRecord v1 omits generation. Same-key recertification
  may match an older head to a newer certificate, then fail the snapshot
  generation check. This fails closed; general renewal needs a protocol and
  migration decision, not permissive fallback through revoked generations.
- **Freshness:** all operators can withhold newer history. A separate trusted
  expected head/checkpoint is needed for rollback detection.
- **MFA deployment:** the released alternate TOTP login is not second-factor
  enforcement. Current MFA additions have scoped negative/race/recovery tests;
  final integrated validation and actual policy activation remain necessary.
  Adding an API does not prove deployed users have enforcement on.
  Recovery codes remain full-account recovery material: a recovery session can
  enroll a replacement device, and fresh proof from that device plus a second
  distinct unused code may reset MFA. Two codes from one sheet are not independent
  factors. The end-to-end exception regression passed; the exception must remain
  disclosed and covered by custody policy.
- **Custody:** separate copies in the same cloud project do not establish
  independent organizational custody. Tools/receipts do not themselves appoint
  custodians or retain keys in independent failure domains.
- **Capacity:** tests of bounded workers are not a production operating envelope.
  Account DB serialization, aggregate memory, HTTP admission/body buffers,
  retention and byte/inode exhaustion need measured workloads with durability.
- **Hardware:** simulator and CI composition tests do not certify physical touch,
  slot policy, OS/reader availability, or universal guardian approval. Treat such
  statements in older specifications as hypotheses to validate on actual hardware.
- **Unavailable adapters:** real CI/provider/repository verification and managed
  KMS remain absent; keep claims and unavailable routes explicit.
- **Review process:** v1.0.26 code/manifest merges used administrator overrides.
  Automated checks do not replace qualifying human peer review.

The transitive `paste` maintenance exception is due **31 December 2026**; see
[dependency policy](DEPENDENCY_AUDIT.md). The browser CI sandbox workaround is a
CI-specific test limitation, separate from production runtime policy.

## Reproducible source evidence pack

The Python standard-library [builder](../scripts/security/build_review_pack.py)
exports only allowed tracked source/test/configuration files and a finite list
of review documents. It excludes runtime vaults, `.agents`, key/environment/DB
files, recovery archives, binaries/build output, ambient logs, and Git remotes.
Synthetic vectors inside source tests are retained. Run the repository secret
scan and inspect the manifest before transferring source; this is not a secret
scanner and no script uploads evidence or contacts anyone.

```powershell
# Internal preparation snapshot: explicitly includes changing source.
python scripts/security/build_review_pack.py --worktree --output "$env:TEMP\CipherVault-internal-review.zip"
python scripts/security/build_review_pack.py --verify "$env:TEMP\CipherVault-internal-review.zip"

# After checks and commit, replace FULL_COMMIT_SHA with the exact final commit.
python scripts/security/build_review_pack.py --ref FULL_COMMIT_SHA --output "$env:TEMP\CipherVault-frozen-review.zip"
python scripts/security/build_review_pack.py --verify "$env:TEMP\CipherVault-frozen-review.zip"
python -m unittest discover -s scripts/security -p test_review_pack.py
```

The manifest records commit/tree, worktree status, exact paths, lengths, and
SHA-256 hashes. Verification reads without extracting and rejects missing,
extra, duplicate, traversing, nonregular and hash-mismatched entries. Output
files are never overwritten. Packs of the same source/reference are repeatable
on the same Python/zlib runtime. Worktree packs are not atomic repository
snapshots; use an immutable commit for a final review.

Hashes prove internal consistency, not publisher authenticity. Authenticate the
archive digest via an agreed trusted channel/signature if handing it to a
separate reviewer. No private runtime material is needed for an initial review;
use synthetic accounts and an isolated test fleet.

## Validation and closure

The [release ledger](../report/DEPLOYMENT_2026-09-30.md) records **826 passed,
0 failed, 3 existing ignored tests**, strict formatting/Clippy, Rust 1.89,
cross-platform CI, Foundry CI, browser/installer/bootstrap checks, signed
artifacts, immutable deployment, and isolated account restore. Those are dated
v1.0.26 results, not results for subsequent changes.

For the final changed commit, run and retain redacted summaries of:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
forge test
python -m unittest discover -s scripts/security -p test_review_pack.py
```

Include repository CI's browser/installer/container/bootstrap/dependency/secret
checks; record ignored and unavailable tests explicitly. Focused operator tests
include `audit_regressions`, `http_auth`, `recovery_auth`,
`service_token_forwarding`, `transport_conformance` and `voucher_enforcement`.
Repeat account policy/TOTP/MFA/secret regressions and CLI `security_beta_gate`,
`historical_epochs`, `run_scoped`, `operator_fail_closed`,
`chaos_federation_drill` and `hardware_token` as appropriate to changes.

Internal exit requires a scoped written finding ledger, evidence for every fix,
explicit residual risks and ownership, a frozen reference, and accurate product
claims. Critical/high unresolved defects block broader exposure. MFA policy,
custody independence, physical hardware, v2 defaults and capacity promises each
need their own implementation and operational evidence. Internal exit must not
be relabeled as independent review or formal proof.
