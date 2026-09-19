use blake2::{Blake2b512, Digest};

use crate::error::CryptoError;

pub const CTX_RECOVERY_SIGNING: &[u8; 8] = b"CV_RSIGN";
pub const CTX_RECOVERY_ENCRYPT: &[u8; 8] = b"CV_RENCR";
pub const CTX_RECOVERY_LOCATOR: &[u8; 8] = b"CV_RLOCA";
pub const CTX_MANIFEST_KEY: &[u8; 8] = b"CV_MANIF";
pub const CTX_FILE_KEY: &[u8; 8] = b"CV_FVERS";
pub const CTX_CHUNK_NONCE: &[u8; 8] = b"CV_CNONC";

/// Domain-separated subkey derivation with a libsodium-`crypto_kdf`-shaped API
/// `(master_key, subkey_id, ctx)` — but a custom Blake2b-512 construction
/// (`CipherVault-KDF-v1` prefix), NOT byte-compatible with libsodium.
/// Derives a 32-byte subkey from a master key using an 8-byte context and subkey index.
pub fn derive_subkey(
    master_key: &[u8; 32],
    subkey_id: u64,
    ctx: &[u8; 8],
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Blake2b512::new();

    // Domain separation prefix
    hasher.update(b"CipherVault-KDF-v1");
    hasher.update(ctx);
    hasher.update(subkey_id.to_le_bytes());
    hasher.update(master_key);

    let result = hasher.finalize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&result[0..32]);

    Ok(subkey)
}

/// Derives a deterministic per-file-version encryption key bound to vault epoch key and file plaintext digest.
pub fn derive_file_version_key(
    master_key: &[u8; 32],
    epoch: u64,
    plaintext_sha256: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Blake2b512::new();
    hasher.update(b"CipherVault-KDF-v1");
    hasher.update(CTX_FILE_KEY);
    hasher.update(epoch.to_le_bytes());
    hasher.update(master_key);
    hasher.update(plaintext_sha256);

    let result = hasher.finalize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&result[0..32]);
    Ok(subkey)
}

/// Derives a deterministic 24-byte XChaCha20 nonce for a chunk bound to file key, chunk index, and chunk digest.
pub fn derive_chunk_nonce(
    file_version_key: &[u8; 32],
    chunk_index: u32,
    chunk_digest: &[u8; 32],
) -> [u8; 24] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"CipherVault-KDF-v1");
    hasher.update(CTX_CHUNK_NONCE);
    hasher.update(chunk_index.to_le_bytes());
    hasher.update(file_version_key);
    hasher.update(chunk_digest);

    let result = hasher.finalize();
    let mut nonce = [0u8; 24];
    nonce.copy_from_slice(&result[0..24]);
    nonce
}

/// Derives a deterministic file version identifier bound to vault ID, epoch, and plaintext SHA-256.
pub fn derive_file_version_id(
    vault_id: &[u8; 32],
    epoch: u64,
    plaintext_sha256: &[u8; 32],
) -> [u8; 32] {
    let mut hasher = Blake2b512::new();
    hasher.update(b"CipherVault-FileVersionID-v1");
    hasher.update(vault_id);
    hasher.update(epoch.to_le_bytes());
    hasher.update(plaintext_sha256);

    let result = hasher.finalize();
    let mut id = [0u8; 32];
    id.copy_from_slice(&result[0..32]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kdf_determinism() {
        let master = [0x42u8; 32];
        let sub1 = derive_subkey(&master, 1, CTX_RECOVERY_SIGNING).unwrap();
        let sub2 = derive_subkey(&master, 1, CTX_RECOVERY_SIGNING).unwrap();
        assert_eq!(sub1, sub2);

        // Different subkey_id yields different output
        let sub3 = derive_subkey(&master, 2, CTX_RECOVERY_SIGNING).unwrap();
        assert_ne!(sub1, sub3);

        // Different context yields different output
        let sub4 = derive_subkey(&master, 1, CTX_RECOVERY_ENCRYPT).unwrap();
        assert_ne!(sub1, sub4);
    }
}
