# Chunk wire protocol v2

Design reviewed during the 30 September 2026 remediation. This is an implementation review, not independent cryptographic certification.

Recovery, certificate, snapshot-record and manifest protocols remain version 1. Chunk wire objects carry version 2 independently. Existing v1 objects and their address/KDF algorithms are unchanged and remain readable. Unknown chunk versions fail closed. **Default captures remain v1 while independent review is open.** Set `CIPHERVAULT_CHUNK_V2_WRITE=1` for explicit v2 opt-in; unset or exactly `0` selects legacy v1. Empty, other and non-Unicode values fail before capture. Library callers can select `ChunkWriteVersion` through `create_snapshot_with_write_version` or `create_snapshot_with_signer_and_write_version` without changing the process environment. Reading both versions is always enabled.

All new derivations use the existing HKDF-SHA256 implementation. The extraction salt is the exact UTF-8 bytes `CipherVault-ChunkWire-v2/HKDF-SHA256`. Expansion info is `u16_le(domain_byte_length) || domain || vault_id[32] || u64_le(epoch) || binding[32]`. No variable-width inputs are concatenated without their length. Domain names and bindings are:

| Output | Input secret | Domain | Binding | Bytes |
|---|---|---|---|---|
| Chunk domain key | Vault epoch key | `chunk-domain-key` | 32 zero bytes | 32 |
| Opaque file version ID | Chunk domain key | `opaque-file-id` | Raw file SHA-256 | 32 |
| Opaque chunk ID | Chunk domain key | `opaque-chunk-id` | Padded chunk SHA-256 | 32 |
| Chunk AEAD key | Chunk domain key | `chunk-aead-key` | Opaque chunk ID | 32 |
| Chunk AEAD nonce | Chunk domain key | `chunk-aead-nonce` | Opaque chunk ID | 24 |

V2 uses the existing canonical CBOR chunk schema. `file_version_id` holds the opaque chunk ID; `chunk_index=0` and `total_chunks=1` indicate an independently addressed chunk. All header fields remain authenticated using the existing fixed-width AAD representation. The ciphertext payload remains XChaCha20-Poly1305 with its prepended nonce. Identical padded chunk bytes in the same vault and epoch derive the same key, nonce, authenticated header and CID. File position and whole-file changes do not alter unchanged chunk objects. Cross-vault and cross-epoch reuse is deliberately excluded.

The encrypted manifest keeps file IDs, paths, a keyed file version ID, raw/padded lengths, whole-file SHA-256 and ordered chunk CIDs. Its existing `file_version_key` slot contains the v2 chunk domain key; decryption verifies it against the supplied epoch key. Decryption validates manifest vault/epoch/version, object vault/epoch/version, canonical v2 position fields, padded lengths, keyed chunk IDs, deterministic nonces, ordered assembly and whole-file SHA-256 before publication. V1 retains its original file-specific key and header semantics.

Operators without the epoch key cannot derive either opaque ID from candidate plaintext using public vault/epoch fields. The protocol still exposes deterministic chunk equality inside an epoch, ciphertext length, object counts, epoch, vault identity and traffic/access patterns. A party with encryption access or a compromised epoch key can confirm candidates. Small-file zero padding can share equal padded chunks whose raw lengths differ; the authenticated encrypted manifest defines the actual file and length. V1 objects retain their public complete-file candidate-confirmation limitation until users recapture them; rewriting local code does not rewrite historical remote objects.

The SHA-256 collision resistance assumption underlies deterministic chunk key/nonce uniqueness. Independently review this construction and its compatibility boundaries before removing the writer gate or broad production claims. Default v1 still has public candidate confirmation and lacks encrypted chunk reuse across edits; F21 is not eliminated in default production. The standard encryption primitives alone do not establish full protocol assurance.
