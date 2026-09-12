use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;

use crate::error::CryptoError;

pub const ARGON2_SALT_LEN: usize = 16;
pub const DERIVED_KEY_LEN: usize = 32;

/// Derives an encryption key from a password and salt using Argon2id.
pub fn derive_key_from_password(
    password: &[u8],
    salt: &[u8; ARGON2_SALT_LEN],
) -> Result<[u8; DERIVED_KEY_LEN], CryptoError> {
    // 64 MiB memory, 3 iterations, 4 lanes
    let params = Params::new(64 * 1024, 3, 4, Some(DERIVED_KEY_LEN))
        .map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut derived_key = [0u8; DERIVED_KEY_LEN];
    argon2
        .hash_password_into(password, salt, &mut derived_key)
        .map_err(|e| CryptoError::PasswordHashError(e.to_string()))?;

    Ok(derived_key)
}

/// Generates a fresh random salt for Argon2id.
pub fn generate_salt() -> [u8; ARGON2_SALT_LEN] {
    let mut salt = [0u8; ARGON2_SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_password_derivation_determinism() {
        let password = b"strong_master_passphrase_test";
        let salt = [0x99u8; ARGON2_SALT_LEN];

        let key1 = derive_key_from_password(password, &salt).unwrap();
        let key2 = derive_key_from_password(password, &salt).unwrap();
        assert_eq!(key1, key2);

        let salt2 = [0x88u8; ARGON2_SALT_LEN];
        let key3 = derive_key_from_password(password, &salt2).unwrap();
        assert_ne!(key1, key3);
    }
}
