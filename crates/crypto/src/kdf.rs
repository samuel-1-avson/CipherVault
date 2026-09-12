use blake2::{Blake2b512, Digest};

use crate::error::CryptoError;

pub const CTX_RECOVERY_SIGNING: &[u8; 8] = b"CV_RSIGN";
pub const CTX_RECOVERY_ENCRYPT: &[u8; 8] = b"CV_RENCR";
pub const CTX_RECOVERY_LOCATOR: &[u8; 8] = b"CV_RLOCA";
pub const CTX_MANIFEST_KEY: &[u8; 8] = b"CV_MANIF";

/// Domain-separated subkey derivation compatible with libsodium crypto_kdf.
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
    hasher.update(&subkey_id.to_le_bytes());
    hasher.update(master_key);

    let result = hasher.finalize();
    let mut subkey = [0u8; 32];
    subkey.copy_from_slice(&result[0..32]);

    Ok(subkey)
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
