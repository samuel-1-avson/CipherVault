# CipherVault Cryptographic Audit Specification & Formal Verification Guide
**Target Audience**: External Cryptographic Auditors (Trail of Bits, Cure53, Kudelski Security), Security Architects, and Verification Engineers.

---

## 1. Executive Summary & Security Objectives

**CipherVault** is a decentralized, zero-knowledge secret backup and disaster recovery platform. The cryptographic protocol is designed to provide:
1. **Confidentiality against Untrusted Operators (IND-CCA2)**: Storage operators observe only opaque, authenticated chunk wire objects indexed by content-derived IDs ($CID = \text{BLAKE2b}(C)$). Operators cannot determine file names, directory structures, variable counts, or plaintext contents.
2. **Side-Channel Resistance & Constant-Time Arithmetic**: Threshold Shamir share evaluation and Galois Field $\text{GF}(2^8)$ arithmetic execute in strictly branchless, constant-time operations.
3. **Hardware-Anchored Device Identity**: Physical capacitive touch confirmation (`Slot 9C` on YubiKey PIV) enforces physical user presence before snapshot head records can be signed.
4. **Memory Hygiene & Zero-Disk Exposure**: Decryption keys and plaintext files are scrubbed using compiler-fenced zeroization (`zeroize::ZeroizeOnDrop`) and injected strictly via in-memory process environment blocks.

---

## 2. Cryptographic Primitives & Parameters

| Primitive | Standard / RFC | Parameterization / Key Size | Domain / Usage |
| :--- | :--- | :--- | :--- |
| **Symmetric AEAD** | RFC 8439 | ChaCha20-Poly1305 (256-bit key, 96-bit nonce, 128-bit MAC tag) | Chunk payload & manifest encryption |
| **Key Derivation (KDF)** | RFC 5869 | HKDF-SHA256 (Extract-then-Expand) | Epoch keys, file version keys, manifest keys |
| **Content Addressing** | RFC 7693 | BLAKE2b-256 (32-byte digest) | Chunk Content Identifiers (CIDs) |
| **Digital Signatures** | RFC 8032 | Ed25519 (EdDSA over Curve25519) | Snapshot records, head commitments, device certs |
| **Key Agreement (ECDH)** | RFC 7748 | X25519 | Clean-machine sealed envelopes & recovery |
| **Threshold Secret Sharing** | Shamir (1979) | Galois Field $\text{GF}(2^8)$ with polynomial $0x11B$ | $M$-of-$N$ guardian disaster recovery |
| **Rolling Chunk Hash** | FastCDC (2016) | Gear Hash Matrix (SplitMix64) | Content-Defined Chunking |

---

## 3. Key Derivation Hierarchy & Domain Separation Registry

All key derivations use domain-separated HKDF-SHA256 or BLAKE2b hashes with explicit context strings:

```
                          Master Recovery Secret R (32 bytes)
                                        |
                 +----------------------+----------------------+
                 | (HKDF: "CipherVault-RecoverySigningKey-v1") | (HKDF: "CipherVault-RecoveryEncryptionKey-v1")
                 v                                             v
       Recovery Signing Key (Ed25519)              Recovery Encryption Key (X25519)
                 |
                 | (Derives Epoch Keys via Sealed Box Envelope)
                 v
         Vault Epoch Key (32 bytes)
                 |
        +--------+--------+----------------------------+
        |                 |                            |
        | ("ManifestKey") | ("FileVersionKey")         | ("ChunkNonce")
        v                 v                            v
  Manifest Key       File Version Key              Chunk Nonce
  (Epoch Bound)      (Vault & File Bound)          (Offset & Digest Bound)
```

### Domain Separation Registry

| Context String | Primitives | Purpose |
| :--- | :--- | :--- |
| `b"CipherVault-RecoverySigningKey-v1"` | HKDF-SHA256 | Derives Ed25519 recovery signing key from $R$ |
| `b"CipherVault-RecoveryEncryptionKey-v1"` | HKDF-SHA256 | Derives X25519 recovery public encryption key from $R$ |
| `b"CipherVault-Locator-v1"` | BLAKE2b-256 | Computes public vault locator from $R_{PK}$ |
| `b"CipherVault-ManifestKey-v1"` | HKDF-SHA256 | Derives manifest encryption key from epoch key |
| `b"CipherVault-FileVersionKey-v1"` | HKDF-SHA256 | Derives deterministic file key bound to epoch |
| `b"CipherVault-ChunkNonce-v1"` | HKDF-SHA256 | Derives deterministic 12-byte AEAD nonce per chunk |
| `b"CIPHERVAULT-POS-V1"` | BLAKE2b-256 | Domain separator for Proof-of-Storage challenges |
| `b"CipherVault-ApprovalChallenge-v1"`| BLAKE2b-256 | Out-of-band authorization challenge hashing |

---

## 4. Constant-Time Galois Field Arithmetic Proofs

In $M$-of-$N$ Shamir's Secret Sharing, secrets are elements of Galois Field $\text{GF}(2^8)$ defined by the irreducible Rijndael polynomial:
$$P(x) = x^8 + x^4 + x^3 + x + 1 \quad (0x11B)$$

### Branchless Multiplication
Classical shift-and-add algorithms branch on $(b \ \& \ 1)$ and high bit overflow $(a \ \& \ 0x80)$, creating microarchitectural timing and branch prediction side channels. CipherVault replaces all branches with bitwise mask operations:

```rust
#[inline(always)]
pub fn gf_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    for _ in 0..8 {
        let mask_b = 0u8.wrapping_sub(b & 1); // 0xFF if LSB set, 0x00 otherwise
        p ^= a & mask_b;

        let mask_hi = 0u8.wrapping_sub((a >> 7) & 1); // 0xFF if MSB set, 0x00 otherwise
        a = (a << 1) ^ (0x1B & mask_hi);
        b >>= 1;
    }
    p
}
```

### Inversion via Fermat's Little Theorem
In $\text{GF}(2^8)$, any non-zero element $a$ satisfies:
$$a^{2^8 - 1} \equiv a^{255} \equiv 1 \implies a^{-1} \equiv a^{254}$$
$a^{254}$ is computed via a fixed-length square-and-multiply chain of 14 operations:
$$254 = 128 + 64 + 32 + 16 + 8 + 4 + 2$$
Because the exponentiation chain has fixed length and calls branchless `gf_mul`, inversion runs in **provably constant time** with zero memory lookup table cache leaks.

---

## 5. Formal Invariants Matrix for Audit Verification

| Invariant ID | Security Property | Formal Definition / Verification Check |
| :--- | :--- | :--- |
| **INV-01** | Zero Plaintext at Rest | SQLite DB keys are protected via OS Keyring (Windows DPAPI / non-Windows authenticated envelope); `recovery_kit_backup.txt` never exists on disk. |
| **INV-02** | Master Secret Scrubbing | `RecoverySecret` implements `ZeroizeOnDrop`; volatile memory is scrubbed with compiler fences immediately after interactive init ceremony. |
| **INV-03** | Cross-Vault Isolation | FastCDC derivation incorporates `VaultEpochKey` and `vault_id`. Identical files across distinct vaults produce mutually uncorrelated ciphertexts. |
| **INV-04** | Hardware Presence | Snapshot commitments with hardware binding strictly require capacitive user touch (`Slot 9C`) via APDU verification before signing. |
| **INV-05** | Atomic Restores | Snapshot restores stage files in `.ciphervault_staging_*`, verify SHA-256 digests against manifest entries, and atomic-rename into working directory. |
| **INV-06** | Zero-Disk Runtime Execution | `ciphervault run` passes decrypted secrets strictly via child process environment blocks in RAM, never flushing buffers to physical storage. |
| **INV-07** | Out-of-Band Quorum | Clean-machine emergency recoveries requiring approval block until cryptographically signed Ed25519 receipts satisfy guardian quorum. |
