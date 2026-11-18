# CipherVault Cryptographic Architecture & Audit Specification

This document specifies the cryptographic primitives, key hierarchy, domain separation, wire formats, and verifiable security invariants of CipherVault (`crates/crypto` and `crates/format`). It is intended as the formal reference package for third-party cryptographic review and audit reproduction.

> **Audit Status Note:** All primitives, domain-separation rules, and fail-closed boundary conditions below are covered by automated property and bitflip tests (`cargo test -p ciphervault-crypto --test crypto_audit_battery` and `cargo test -p ciphervault-format --test schema_battery`). External third-party review should inspect `crates/crypto/` and `crates/format/` against this specification.

---

## 1. Cryptographic Primitives & Crates

| Purpose | Algorithm / Construction | Parameters | Crate / Module |
|---|---|---|---|
| Symmetric AEAD | XChaCha20-Poly1305 | 256-bit key, 192-bit nonce, 128-bit Poly1305 tag | `chacha20poly1305` (`crates/crypto/src/aead.rs`) |
| Legacy / Recovery KDF | Domain-separated BLAKE2b-512 | `"CipherVault-KDF-v1"` prefix, 8-byte context, 64-bit LE index | `blake2` (`crates/crypto/src/kdf.rs`) |
| Chunk Protocol v2 KDF | HKDF-SHA256 | Salt `b"CipherVault-ChunkWire-v2/HKDF-SHA256"`, length-prefixed domain | `hkdf` + `sha2` (`crates/crypto/src/chunk_v2.rs`) |
| Password / Passphrase KDF | Argon2id (v0x13) | 64 MiB memory, 3 iterations, 4 lanes, 16-byte random salt, 32-byte output | `argon2` (`crates/crypto/src/password.rs`) |
| Digital Signatures | Ed25519 (strict verification) | `verify_strict` + `is_weak()` rejection, prefix-free domain tags | `ed25519-dalek` (`crates/crypto/src/signatures.rs`) |
| Sealed-Box Asymmetric Wrap | Ephemeral X25519 + BLAKE2b-512 + XChaCha20-Poly1305 | Contributory DH check (`was_contributory()`) | `x25519-dalek` (`crates/crypto/src/sealed_box.rs`) |
| Threshold Recovery Sharing | Shamir Secret Sharing over $\text{GF}(2^8)$ | Rijndael polynomial $0\text{x}11\text{B}$, branchless `gf_mul`, per-byte evaluation | `crates/crypto/src/shamir.rs` |
| Canonical Wire Encoding | Deterministic CBOR (RFC 8949 §4.2) | Canonical map ordering / byte-string framing | `ciborium` (`crates/format/src/canonical.rs`) |
| Memory Hygiene | Zero-on-drop wrappers | `Zeroizing`, `ZeroizeOnDrop` on keys, shares, and decrypted buffers | `zeroize` |

---

## 2. Key Hierarchy & Isolation

1. **Master Recovery Secret ($R \in \{0,1\}^{256}$)** — Generated via OS CSPRNG (`rand::thread_rng()`), optionally split via $M$-of-$N$ Shamir over $\text{GF}(2^8)$ or sealed in `CVKB1` passphrase envelopes (`Argon2id` + `XChaCha20-Poly1305`).
   - `CTX_RECOVERY_SIGNING` (`b"CV_RSIGN"`, index `1`) $\rightarrow$ Ed25519 recovery root signing keypair.
   - `CTX_RECOVERY_ENCRYPT` (`b"CV_RENCR"`, index `1`) $\rightarrow$ X25519 recovery encryption keypair.
   - `CTX_RECOVERY_LOCATOR` (`b"CV_RLOCA"`, index `1`) $\rightarrow$ 32-byte opaque storage locator.
2. **Vault Epoch Key ($V_e \in \{0,1\}^{256}$)** — Rotatable epoch root key wrapped to the recovery public key via `EpochEnvelope` using `seal_box`.
   - `CTX_MANIFEST_KEY` (`b"CV_MANIF"`, index `epoch`) $\rightarrow$ Manifest XChaCha20-Poly1305 encryption key.
   - `CTX_ANCHOR_SALT` (`b"CV_ANCHR"`) $\rightarrow$ Deterministic per-head anchor commitment salt.
   - `derive_v2_chunk_domain_key(V_e, vault_id, epoch)` $\rightarrow$ HKDF-SHA256 domain key bound to `(vault_id, epoch)`.
3. **Chunk Protocol v2 Content Addressing & Encryption (`crates/crypto/src/chunk_v2.rs`)**
   - `opaque-file-id`: keyed file-version identifier from `(domain_key, vault_id, epoch, plaintext_sha256)`.
   - `opaque-chunk-id`: keyed chunk identifier from `(domain_key, vault_id, epoch, chunk_plaintext_sha256)`.
   - `chunk-aead-key` / `chunk-aead-nonce`: deterministic 256-bit key and 192-bit nonce derived from `(domain_key, vault_id, epoch, opaque_chunk_id)` via HKDF-SHA256.
4. **Scoped Secret Envelope (`crates/crypto/src/envelope.rs`)**
   - Every scoped secret version generates a fresh random 256-bit `DataEncryptionKey`.
   - Ciphertext is sealed with XChaCha20-Poly1305 under fixed-width 90-byte `scope_aad`: `b"CipherVault-ScopeAAD-v1" || tenant_id[16] || project_id[16] || env_id[16] || secret_id[16] || version_be[4]`.
   - DEKs are wrapped by `KeyWrappingService` (`LocalKekService` with AAD `b"cv-kek-wrap-v1" || kek_id`).

---

## 3. Domain Separation Registry

### 3.1 Ed25519 Signature Domains
All signatures compute `sign_with_domain` / `verify_with_domain` over:
```
"CipherVault-Ed25519-v1:" || context || ":" || message
```
where `context` is asserted/checked to be non-empty and free of `':'` so the `context || ":" || message` boundary is strictly prefix-free.

Registered contexts:
- `genesis_record` — Vault `GenesisRecord`
- `device_certificate` — Device authorization `DeviceCertificate`
- `epoch_envelope` — `EpochEnvelope` wrapping $V_e$
- `snapshot_record` — `SnapshotRecord` (CBOR manifest + parent CIDs + epoch + counter + `authority_generation`)
- `head_record` — `HeadRecord` v1/v2 head pointer (`HEAD_RECORD_VERSION_V2`)
- `operator_challenge` — Mutual challenge-response auth with storage operators
- `operator_join_invite` — Fleet-signed operator join invitation
- `operator_pos` — Operator Proof-of-Storage attestation
- `dpop-v1` — Account service DPoP request proof
- `account_login` — Account device session login proof
- `placement_update` — Maintenance placement update
- `audit_log_entry` — Tamper-evident local agent audit chain signatures (where applicable)

### 3.2 AEAD Associated Data (AAD) Bindings
- **Manifest**: `b"CipherVault-Manifest:" || vault_id[32] || epoch_le[8]`
- **Chunk Wire Object**: `version_le[4] || vault_id[32] || file_version_id[32] || chunk_index_le[4] || total_chunks_le[4] || declared_padded_length_le[4] || key_epoch_le[8]`
- **Sealed Box**: `b"CipherVault-SealedBox"` (with `ephemeral_pk || recipient_pk || shared_secret` bound in `CipherVault-BoxSeal-v1`)
- **Passphrase Backup (`CVKB1`)**: `b"CVKB1" || kdf_id[1] || salt[16] || nonce[24]`
- **OS Keyring (`CVK2`)**: `b"CipherVault-OS-Keyring-v2"`
- **Scoped Secrets**: `b"CipherVault-ScopeAAD-v1" || tenant[16] || project[16] || env[16] || secret[16] || version_be[4]`

---

## 4. Hardened Invariants & Security Fixes

1. **Strict Ed25519 Verification & Small-Order Rejection (`crates/crypto/src/signatures.rs`)**:
   - `verify_with_domain` rejects weak/small-order public keys (`verifying_key.is_weak()`) and validates signatures via `VerifyingKey::verify_strict`, preventing cofactor/torsion signature malleability and non-canonical $S \ge L$ encodings.
   - `context` is enforced non-empty and `':'`-free in both `sign_with_domain` and `verify_with_domain`.
2. **Non-Contributory X25519 Rejection (`crates/crypto/src/sealed_box.rs`)**:
   - Both `seal_box` and `open_sealed_box` reject low-order points when `!shared_point.was_contributory()`.
3. **Authenticated Threshold Verification (`crates/crypto/src/shamir.rs`)**:
   - Callers knowing $M$ use `combine_shares_with_threshold(shares, M)` so under-threshold subsets fail closed before reconstruction; `gf_mul` uses constant-iteration bit-mask arithmetic without secret-dependent branches or lookup tables.
4. **Indistinguishable Decryption Errors**:
   - `decrypt_chunk`, `decrypt_with_nonce`, `open_secret_value`, `LocalKekService::unwrap_dek`, and `open_passphrase_backup` map truncation, unknown header/KDF versions, and authentication tag failures identically to `AuthTagVerificationFailed`.

---

## 5. Audit Reproduction Commands

```bash
cargo test -p ciphervault-crypto --test crypto_audit_battery
cargo test -p ciphervault-crypto
cargo test -p ciphervault-format --test schema_battery
```
