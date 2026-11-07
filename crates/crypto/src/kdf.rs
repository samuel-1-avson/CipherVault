use blake2::{Blake2b512, Digest};

use crate::error::CryptoError;

pub const CTX_RECOVERY_SIGNING: &[u8; 8] = b"CV_RSIGN";
pub const CTX_RECOVERY_ENCRYPT: &[u8; 8] = b"CV_RENCR";
pub const CTX_RECOVERY_LOCATOR: &[u8; 8] = b"CV_RLOCA";
pub const CTX_MANIFEST_KEY: &[u8; 8] = b"CV_MANIF";
pub const CTX_FILE_KEY: &[u8; 8] = b"CV_FVERS";
pub const CTX_CHUNK_NONCE: &[u8; 8] = b"CV_CNONC";
pub const CTX_ANCHOR_SALT: &[u8; 8] = b"CV_ANCHR";

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

/// Derives the deterministic per-snapshot anchor salt bound to the vault
/// epoch key and snapshot record CID. The salt is recoverable by the vault
/// owner (who holds the epoch key via replicated recovery records) without
/// any new network calls, and opaque to everyone else — so the on-chain
/// salted commitment stays verifiable after local state loss. Deterministic
/// by construction: concurrent push retries converge on the same salt.
pub fn derive_anchor_salt(
    epoch_key: &[u8; 32],
    head_cid: &[u8; 32],
) -> Result<[u8; 32], CryptoError> {
    let mut hasher = Blake2b512::new();
    hasher.update(b"CipherVault-KDF-v1");
    hasher.update(CTX_ANCHOR_SALT);
    hasher.update(epoch_key);
    hasher.update(head_cid);

    let result = hasher.finalize();
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&result[0..32]);
    Ok(salt)
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

    #[test]
    fn test_anchor_salt_determinism_and_binding() {
        let epoch_key = [0x11u8; 32];
        let head_a = [0xAAu8; 32];
        let head_b = [0xBBu8; 32];

        // Deterministic: same inputs always converge (push retries agree).
        let s1 = derive_anchor_salt(&epoch_key, &head_a).unwrap();
        let s2 = derive_anchor_salt(&epoch_key, &head_a).unwrap();
        assert_eq!(s1, s2);

        // Bound to both inputs: different head or epoch key diverges.
        assert_ne!(s1, derive_anchor_salt(&epoch_key, &head_b).unwrap());
        assert_ne!(s1, derive_anchor_salt(&[0x22u8; 32], &head_a).unwrap());

        // Domain-separated from the other KDF outputs on the same master.
        assert_ne!(s1, derive_subkey(&epoch_key, 1, CTX_MANIFEST_KEY).unwrap());
    }
}
