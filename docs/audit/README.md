# CipherVault — external audit engagement pack

Everything an independent cryptographic/security auditor needs to
scope, price, and start an audit. Snapshot: `main` @ `ea22290`
(tag `v1.0.32`), November 2026. This pack is an *invitation and
scope document* — CipherVault has **not** had an external audit;
see `SECURITY.md` → "Audit status" for the honest current state.

## 1. What we ask for

1. A cryptographic protocol review of the items in §3 (design +
   implementation), with findings rated by severity and exploit
   preconditions.
2. A focused code review of the in-scope crates in §4 for the
   invariant violations listed in §5.
3. A written report we may publish in full, plus a re-test of fixes
   for any critical/high findings.
4. A short public statement (letter or signed summary) we can cite
   verbatim once remediation is verified.

Out of scope unless separately agreed: the account service's web
stack, the landing/dashboard UI, CI/infra, and social engineering.

## 2. System in one paragraph

Client-side encrypted secret backup. A Rust CLI encrypts files on
the user's machine (XChaCha20-Poly1305 over FastCDC chunks), signs
snapshot/head records (Ed25519), and replicates ciphertext to three
independent storage operators that authenticate devices by
challenge/session and hold only opaque objects. Recovery is by an
offline paper kit (master secret R), M-of-N Shamir guardian shares,
or a passphrase-wrapped key backup. A Hermes Agent plugin guards
agent tool calls around the vault and keeps a hash-chained,
device-signed, fleet-anchored audit log. Full design spec:
`docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`; guarantees and known
limits: `docs/CURRENT_SECURITY_GUARANTEES.md`; threat model:
`docs/audit/THREAT_MODEL.md`.

## 3. Cryptographic scope (highest value first)

| # | Component | Where | Questions we most want answered |
|---|---|---|---|
| C1 | Legacy custom KDF (Blake2b-512, `CipherVault-KDF-v1` prefix + 8-byte context, truncated 32 B) | `crates/crypto`, spec §3 | Is the construction sound as a PRF/KDF for key separation? Any cross-domain collisions? |
| C2 | Deterministic file keys + chunk nonces (`CV_FVERS`/`CV_CNONC`) | `crates/snapshot`, `crates/crypto` | Leakage model of v1 (candidate-file confirmation) — is our documented leakage complete? Nonce-reuse conditions? |
| C3 | Opt-in v2 chunk protocol (HKDF-SHA256, keyed opaque IDs) | `crates/snapshot/CHUNK_PROTOCOL_V2.md` | Does v2 actually close the v1 confirmation leak? Domain separation correctness. (Ships opt-in *pending this review*.) |
| C4 | Shamir M-of-N over GF(2^8), branchless `gf_mul`, Fermat inversion | `crates/recovery`, spec §4 | Share privacy below threshold; side-channel claims scoped correctly? |
| C5 | Recovery kit format (v1 + v2 checksum), passphrase backup (Argon2id, `CVKB1`) | `crates/recovery` | Kit integrity, downgrade paths, KDF parameters. |
| C6 | Sealed epoch envelopes (X25519 sealed box), device certificates, recovery signing | `crates/format`, `crates/local-store` | Envelope binding, cert authority generations, replay/rollback of heads. |
| C7 | Operator protocol: challenge/session auth, signed proof-of-storage (`CIPHERVAULT-POS-V1`), lease receipts | `crates/storage`, `services/operator` | Session scope binding, PoS soundness, receipt forgery. |
| C8 | Audit chain: hash-chained device-signed entries, signed fleet checkpoints | `crates/local-store` (`agent_audit`), `apps/cli/src/commands/agent_log.rs` | Chain/anchor forgery or truncation under a same-user attacker; what the proof does and does not establish. |

## 4. Code scope

In scope (Rust workspace, ~14 crates): `crates/crypto`,
`crates/format`, `crates/snapshot`, `crates/recovery`,
`crates/local-store`, `crates/storage`, `crates/chain`,
`services/operator`, the CLI surfaces that touch key material
(`apps/cli/src/commands/{recover,recovery_*,push,agent_log,run}.rs`),
and the Hermes plugin's guard/scrub layer
(`plugins/ciphervault/__init__.py`, Python). Everything else is
context.

## 5. Invariants we claim (test these)

1. Operators never receive plaintext or keys; all stored objects
   are ciphertext or public records.
2. A snapshot/head not signed by an authorized device key (correct
   authority generation) is rejected everywhere.
3. Below-threshold Shamir shares reveal nothing about R.
4. The audit chain detects any mid-chain edit, deletion, or
   reorder, and any row-content edit. Tail truncation is detected
   only against the fleet anchor (`agent-log verify-remote` fails
   on fewer entries than anchored or on divergence at the anchored
   position); a same-OS-user attacker who can sign as the device
   can re-forge and re-anchor, and is out of scope (audit pack §7).
5. Secret values never appear in plugin tool outputs, the audit
   log, or CLI JSON surfaces (paths/names/counts/hashes only).
6. Recovery from kit/shares on a clean machine reproduces the exact
   tracked plaintext (hash-verified), and stale-kit vault-ID
   mismatches are refused.

## 6. Reproduce our evidence

```bash
cargo test --workspace --locked            # 1,100+ tests
RUSTFLAGS="-D warnings" cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test -p ciphervault-crypto -p ciphervault-recovery --locked   # KATs live beside the code
python3 -m pytest plugins/ciphervault/tests -q
```

Test evidence for the release: `report/TEST_EVIDENCE_v1.0.32.md`.
Known-answer tests for the legacy KDF are in `crates/crypto`;
chunk-protocol vectors in `crates/snapshot`.

## 7. Known limitations (we will not ask you to rediscover these)

- v1 chunking leaks candidate-file confirmation + length/access
  patterns (documented; v2 is the opt-in fix, §3-C3).
- Same-OS-user attacker is out of scope for the local audit chain
  (hardware keys via YubiKey PIV are the mitigation).
- Release `SHA256SUMS.txt` is built locally and unsigned while
  GitHub Actions billing is suspended; plugin bootstrap pins the
  binary SHA-256 in source to compensate.
- No reproducible-build attestation yet; no SBOM published.
- This list itself is in scope for correction: tell us what we
  missed.

## 8. Logistics

- Contact: GitHub private vulnerability reporting on
  `samuel-1-avson/CipherVault` (see `SECURITY.md`); audit
  coordination via GitHub issues/discussions if preferred.
- We can provide: a seeded demo vault, a 3-operator local fleet
  (`docker-compose.yml`), test vectors, and engineering time for
  walkthroughs.
- Please quote: scope options (C1–C8 full or staged), fixed fee or
  day rate, earliest start, report licence (we require the right
  to publish), and re-test terms.
