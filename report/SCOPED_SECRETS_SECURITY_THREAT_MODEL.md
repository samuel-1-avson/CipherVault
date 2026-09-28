# Deliverable G — Security & Threat Model: Scoped Secrets

**Version:** 2.5.0 · **Date:** 2026-09-27 · **Parent report:** [SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md](./SCOPED_SECRET_MANAGEMENT_RESEARCH_REPORT.md) (§7, §15, §16, S1, S3, §27)

## 1. Trust boundaries

```text
[Attacker-visible]  Git repos · operator replicas (ciphertext) · public API surface · CI logs
        ║ TLS / OIDC / webauthn / PIV ║
[Trust boundary]  control plane (authn → authorize() → scope-predicated queries → KMS → decrypt → audit)
        ║ envelope (keys never beside ciphertext) ║
[Highest trust]   KMS/HSM · audit chain store · break-glass Shamir custodians
```

Key separation: compromise of any single layer below the KMS yields ciphertext and/or metadata only — never plaintext at scale.

## 2. Threat catalogue (20 threats; full 7-field analysis in S1)

| ID | Threat | Severity | Primary mitigation | Test |
|----|--------|----------|--------------------|------|
| T1 | Cross-project access | Critical | Central `authorize()` + scope predicates + scope-bound AAD | IDOR matrix: A-token × B-resource ⇒ 404 |
| T2 | Cross-tenant access | Critical | `tenant_id` leading columns + RLS + per-tenant KEKs | Tenant-isolation harness, all endpoints |
| T3 | IDOR/BOLA | High | Resolve-then-authorize; UUIDv7; uniform 404 | BOLA matrix + path-param fuzz |
| T4 | Name enumeration | Medium | Indistinguishable 404s; rate limits; scope-only search | Timing/status indistinguishability probe |
| T5 | Repo binding bypass | High | Immutable provider IDs; OIDC `repository_id` verify | Rename/transfer/fork fixture suite |
| T6 | Environment escalation | Critical | Env-scoped token claims; branch policy; dual prod | Dev-token-vs-prod matrix |
| T7 | Membership escalation | High | Least-privilege invites; dual-admin `admin` grants | Lifecycle + stale-invite replay tests |
| T8 | Stale bindings | Medium | Webhooks + reconcile; `active→suspended→revoked` | Webhook simulation suite |
| T9 | Deleted-project retention | Med-High | Soft-delete → crypto-shred → purge; slug quarantine | Delete→recreate-slug ⇒ zero residue |
| T10 | Leakage via logs | High | `SecretValue` redaction; digest-only audit; entropy gate | Canary-absence tests on all outputs |
| T11 | Leakage via backups | High | Split-plane backups; backup KEK; quorum restore | Restore-without-KMS ⇒ ciphertext only |
| T12 | Malicious CI identity | Critical | Least-privilege job tokens; fork⇒dev-only; ref allowlist | Malicious-step simulation |
| T13 | Token replay | High | 5–15 min TTL; DPoP/mTLS option; jti denylist | Cross-host/expired/single-use matrix |
| T14 | Insider access | Critical | Split knowledge; dual control; JIT elevation; hash-chained audit | Dual-control + tamper + anomaly tests |
| T15 | Database compromise | High | KMS-held keys; metadata minimization; param queries | Dump-without-KMS ⇒ zero plaintext |
| T16 | Compromised app server | Critical | Enclave option; zeroize; hardened hosts; KMS anomaly alerts | Key-rotation drill within SLO |
| T17 | Compromised workstation | High | PIV/passkey prod gates; short grants; posture checks | Posture + revoke-propagation tests |
| T18 | Cache poisoning/collisions | High | `cv:sec:{t}:{p}:{e}:{id}:{v}` keys; ciphertext-only | Key-separation + forged-entry tests |
| T19 | Version mix-ups | Med-High | Transactional pointer; deploy pinning; rollback-as-version | Concurrent-rotate linearizability |
| T20 | Rotation races | Med-High | Row locks; idempotency keys; verify-before-commit | Double-rotate + kill-mid-rotate tests |

Current-codebase mitigations that carry over `[Verified in code]`: XChaCha20-Poly1305 + domain-separated KDF (`crates/crypto`), zeroized key types (`keys.rs`), ciphertext-only operators (zero decrypt hits in `services/operator/src`), vault-bound sessions (`handlers.rs:183-211`), fail-closed strict auth default (`handlers.rs:40-44`), `mask_value` diff redaction (`diff.rs`), PIV touch policy (`piv.rs`), deliberate capability-URL recovery reads (ADR-006).

## 3. Security invariants (non-negotiable; each is an automated gate)

1. No caller retrieves a secret outside an authorized scope (server-side enforcement).
2. Secret names alone are never authorization context (full scope path required).
3. Tenant boundaries enforced server-side (predicates + RLS + per-tenant KEKs).
4. Repository names are never durable identity (immutable provider IDs only).
5. Plaintext never appears in logs, audit, errors, traces, metrics, or search indexes.
6. Search cannot reveal unauthorized secret metadata (scope predicates precede ranking).
7. Movement/rebinding is an audited privileged operation (dual control for prod).
8. Environment escalation requires explicit authorization (no implicit dev→prod).
9. Cache keys include full scope + version; cached values are ciphertext-only.
10. Rotation preserves logical identity and append-only version history.
11. Keys never stored beside ciphertext they protect (split-plane rule).
12. Every mutation emits a hash-chained audit event before acknowledging success.

## 4. Testing requirements summary

Unit (S6-U) → integration incl. BOLA matrix (S6-I) → security suite incl. entropy/canary gates (S6-S) → E2E login-to-rotate flows + migration + game-day (S6-E). Invariants 1–12 each map to ≥1 build-failing test; invariants 3 and 10 additionally property-tested. Pen-test re-run required on T1–T7, T10, T13, T18 before Phase 10 exit.
