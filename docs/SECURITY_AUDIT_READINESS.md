# Security Audit Readiness Package (Blocker 1)

**Status:** `BLOCKED — EXTERNAL AUDIT PENDING`. No third-party audit or
penetration test has occurred. This package is everything an auditor needs
to start; it is not a substitute for the audit.

## 1. Audit scope (proposed)

- Cryptographic implementation: `crates/crypto`, `crates/format`
  (canonical CBOR, CIDs), KDF registry, Shamir GF(2⁸), AEAD usage.
- Anchor path: `contracts/CipherVaultRegistry.sol`, `crates/storage/src/chain.rs`,
  checkpoint feed sign/verify (`apps/cli/src/commands/feed.rs`,
  `apps/cli/src/dashboard/finality.rs`).
- Operator authN/authZ: `services/operator/src/{state,handlers}.rs`
  (challenges, sessions, enrollment, revocation), `crates/storage/src/{invites,vouchers}.rs`.
- Release supply chain: `apps/cli/src/commands/{update,release}.rs`,
  `.github/workflows/release.yml` (+ Cosign container signing).
- Deployment boundaries: `deploy/`, `scripts/gcp/`, Caddy configs,
  dashboard account proxy, fleet firewall posture.
- Explicitly out of scope for round 1: landing page marketing JS,
  TUI widgets (non-crypto), archived spikes.

## 2. System architecture (summary)

Client CLI/TUI (`apps/cli`) encrypts locally (XChaCha20-Poly1305,
deterministic nonces from the custom Blake2b KDF) into content-addressed
chunks (SHA-256 CIDs), replicates across 3+ operator daemons
(`services/operator`, HTTP today, libp2p dual-mode available) with quorum
leases, PoS receipts, and recovery logs. Checkpoints anchor to
`CipherVaultRegistry` on Arbitrum (Sepolia today). A signed public
checkpoint feed mirrors anchor evidence for the explorer. Full detail:
`docs/DECENTRALIZED_ARCHITECTURE_SPEC.md`,
`docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md`, `docs/SYSTEM_WORKFLOW.md`.

## 3. Threat model

- Operators are untrusted for confidentiality (see only opaque chunks).
- Network attacker: TLS + signed protocols; must not forge membership,
  sessions, vouchers, feeds, or releases.
- Malicious joiner: ticket-bound, probation-limited, quota/voucher-bound.
- Compromised release pipeline: must not ship unsigned binaries (Blocker 4
  verification), must not ship unsigned images (Cosign).
- Lost keys: defined per key (see §5); fleet-seed loss = membership
  re-bootstrap (accepted, drilled).

## 4. Trust boundaries

Client vault ↔ operator fleet (authN sessions, vouchers); fleet nodes ↔
each other (fleet-signed tickets, signed descriptors/heartbeats); fleet ↔
chain (anchor payer, registry reads); release pipeline → users (pinned
release key); publisher worker → dashboard (pinned publisher key);
anonymous internet → fleet (health/metrics/info + recovery reads only
after re-close — currently WIDER, see Blocker 3).

## 5. Key-management model

`docs/KEY_CEREMONIES_AND_BACKUPS.md` (+ rotation evidence in
`docs/KEY_ROTATION_DRILLS.md`). Inventory: fleet seed (offline file),
operator keys (per-node, `0600`, rotation keeps timestamped backups),
publisher key (worker env + dashboard pin — rotation drilled 2026-09-26),
release signing key (CI secret + offline copy — new with Blocker 4),
account TOTP (Secret Manager), anchor payer (manual custody), user master
secret R (paper + Shamir guardians), device keys (OS keyring).

## 6. Cryptographic assumptions (for auditor challenge)

Custom Blake2b KDF (`CipherVault-KDF-v1`, NOT HKDF — compatibility risk
explicitly documented in ADR-001); deterministic XChaCha20 nonces derived
per chunk (nonce-misuse resistance depends on KDF soundness — flag for
deep review); branchless `gf_mul` only (surrounding loops not claimed
constant-time); Ed25519/X25519 via audited crates (`ed25519-dalek`,
`x25519-dalek`); SHA-256 CIDs; domain separation strings enumerated in
the crypto audit spec.

## 7. Known limitations / unresolved risks (self-reported)

1. No external audit/pen test (this blocker).
2. Fleet currently open-write (Blocker 3, re-close decision recorded,
   live execution pending).
3. Custom KDF unreviewed externally (highest-priority audit target).
4. Deterministic nonces: sound only if (file, epoch, vault) uniqueness holds.
5. Vouchers are bearer credentials by design (sender-constrained binding future work).
6. Anchor on Sepolia testnet (Blocker 5); mainnet promotion gated on audit.
7. Legal review of third-party ciphertext storage pending (Blocker 6).
8. Single offline fleet seed (no quorum minting in production path; v2
   quorum tickets exist — ADR-011 — but the live ceremony is single-key).

## 8. Test suites / reproduction

- `cargo test --workspace --locked` (workspace gate; 136 CLI unit tests
  green 2026-09-26), `cargo clippy --all-targets -- -D warnings`,
  `cargo fmt --check`, `forge test` (contracts).
- Security-focused: `apps/cli/tests/security_beta_gate.rs`,
  `chaos_federation_drill.rs`, operator `http_auth.rs`,
  `voucher_enforcement.rs`, `transport_conformance.rs`, feed verify tests,
  updater signature tests, `publisher_key_rotation_drill`.
- Repro: stable Rust, `--locked`; drill harness pattern in
  `docs/KEY_ROTATION_DRILLS.md` (loopback nodes, scripted HTTP).

## 9. Security-sensitive configuration

`CIPHERVAULT_FLEET_KEY(s)`, `CIPHERVAULT_OPERATOR_{STRICT_AUTH,
REQUIRE_ENROLLMENT,SERVICE_TOKEN}`, `CIPHERVAULT_PUBLIC_CHECKPOINT_{SIGNING_KEY_HEX,PUBLISHER_KEY,FEED}`,
`CIPHERVAULT_RELEASE_SIGNING_KEY` (CI secret only),
`CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`, anchor RPC/chain/contract vars,
account TOTP secret, `--require-write-vouchers`.

## 10. Audit checklist (entry/exit)

Entry: scope §1 agreed; code frozen at a tagged commit; testnet access +
rehearsal drill scripts provided; known-risk list §7 acknowledged.
Exit: findings with severity + remediation status; retest of fixes;
written conclusion. Promotion gates (`docs/MAINNET_ANCHOR_PROMOTION.md`)
stay red until exit criteria are met.

## 11. Internally discovered findings (this session)

- None requiring product changes: rotation, re-close mechanics, and
  updater verification behaved as designed under live testing.
- Process findings: (a) drill evidence hygiene (fresh dirs per run);
  (b) service-token header is `X-CipherVault-Service-Token`, not
  `Authorization: Bearer` — runbook authors must copy exactly;
  (c) `ui --serve` dashboard tolerates empty feeds (pin still enforced).
