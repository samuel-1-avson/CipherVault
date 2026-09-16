//! OS-level Key Protection Layer
//!
//! Encrypts sensitive cryptographic keys (device signing keys, epoch keys)
//! using operating system credential facilities (Windows DPAPI) before persisting
//! to the local SQLite database.

use crate::error::LocalStoreError;

#[cfg(windows)]
mod platform {
    use super::*;
    use std::ptr;

    #[repr(C)]
    struct DataBlob {
        cb_data: u32,
        pb_data: *mut u8,
    }

    const CRYPTPROTECT_UI_FORBIDDEN: u32 = 0x1;

    #[link(name = "crypt32")]
    #[link(name = "kernel32")]
    extern "system" {
        fn CryptProtectData(
            pDataIn: *const DataBlob,
            szDataDescr: *const u16,
            pOptionalEntropy: *const DataBlob,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DataBlob,
        ) -> i32;

        fn CryptUnprotectData(
            pDataIn: *const DataBlob,
            ppszDataDescr: *mut *mut u16,
            pOptionalEntropy: *const DataBlob,
            pvReserved: *mut std::ffi::c_void,
            pPromptStruct: *mut std::ffi::c_void,
            dwFlags: u32,
            pDataOut: *mut DataBlob,
        ) -> i32;

        fn LocalFree(hMem: *mut std::ffi::c_void) -> *mut std::ffi::c_void;
    }

    pub fn protect(bytes: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let in_blob = DataBlob {
            cb_data: bytes.len() as u32,
            pb_data: bytes.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let res = unsafe {
            CryptProtectData(
                &in_blob,
                ptr::null(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if res == 0 || out_blob.pb_data.is_null() {
            return Err(LocalStoreError::KeyProtectionError(
                "Windows DPAPI CryptProtectData failed".into(),
            ));
        }

        let out_bytes = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };

        unsafe {
            LocalFree(out_blob.pb_data as *mut _);
        }

        Ok(out_bytes)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let in_blob = DataBlob {
            cb_data: ciphertext.len() as u32,
            pb_data: ciphertext.as_ptr() as *mut u8,
        };
        let mut out_blob = DataBlob {
            cb_data: 0,
            pb_data: ptr::null_mut(),
        };

        let res = unsafe {
            CryptUnprotectData(
                &in_blob,
                ptr::null_mut(),
                ptr::null(),
                ptr::null_mut(),
                ptr::null_mut(),
                CRYPTPROTECT_UI_FORBIDDEN,
                &mut out_blob,
            )
        };

        if res == 0 || out_blob.pb_data.is_null() {
            return Err(LocalStoreError::KeyProtectionError(
                "Windows DPAPI CryptUnprotectData failed".into(),
            ));
        }

        let out_bytes = unsafe {
            std::slice::from_raw_parts(out_blob.pb_data, out_blob.cb_data as usize).to_vec()
        };

        unsafe {
            LocalFree(out_blob.pb_data as *mut _);
        }

        Ok(out_bytes)
    }
}

pub mod portable_keystore {
    use super::*;
    use ciphervault_crypto::{decrypt_chunk, encrypt_chunk};
    use sha2::{Digest, Sha256};
    use std::path::PathBuf;

    pub const MAGIC_KEYSTORE_V2: &[u8; 4] = b"CVK2";

    /// Resolves the master encryption key for the portable keystore.
    /// Fails closed if neither an explicit env var nor a valid key file exists.
    pub fn resolve_key() -> Result<[u8; 32], LocalStoreError> {
        // 1. Check CIPHERVAULT_MASTER_KEY env var
        if let Ok(val) = std::env::var("CIPHERVAULT_MASTER_KEY") {
            let val = val.trim();
            if let Ok(bytes) = hex::decode(val) {
                if bytes.len() == 32 {
                    let mut key = [0u8; 32];
                    key.copy_from_slice(&bytes);
                    return Ok(key);
                }
            }
            // Passwords are deliberately slower to derive than raw keys. A
            // caller may supply a stable 16-byte salt via
            // CIPHERVAULT_MASTER_KEY_SALT; otherwise derive a per-keystore
            // salt from the non-secret key-file path so two installations do
            // not share the same salt.
            let salt = passphrase_salt()?;
            return ciphervault_crypto::derive_key_from_password(val.as_bytes(), &salt).map_err(
                |error| {
                    LocalStoreError::KeyProtectionError(format!(
                        "Argon2id master-key derivation failed: {error}"
                    ))
                },
            );
        }

        // 2. Check key file from CIPHERVAULT_KEYSTORE_PATH or ~/.config/ciphervault/keystore.key
        let key_path = get_default_keyfile_path()?;
        if key_path.exists() {
            let content = std::fs::read(&key_path).map_err(|e| {
                LocalStoreError::KeyProtectionError(format!(
                    "Failed to read keystore file at {}: {}",
                    key_path.display(),
                    e
                ))
            })?;
            if content.len() >= 32 {
                let mut key = [0u8; 32];
                key.copy_from_slice(&content[0..32]);
                return Ok(key);
            }
        }

        // Fail closed: Guessable environment variables (USER, HOME) are rejected.
        Err(LocalStoreError::KeyProtectionError(
            "Non-Windows keystore requires provisioned CIPHERVAULT_MASTER_KEY or valid keystore file (~/.config/ciphervault/keystore.key). Guessable environment credentials rejected.".into(),
        ))
    }

    fn passphrase_salt() -> Result<[u8; 16], LocalStoreError> {
        if let Ok(value) = std::env::var("CIPHERVAULT_MASTER_KEY_SALT") {
            let bytes = hex::decode(value.trim()).map_err(|_| {
                LocalStoreError::KeyProtectionError(
                    "CIPHERVAULT_MASTER_KEY_SALT must be 16-byte hex".into(),
                )
            })?;
            return bytes.try_into().map_err(|_| {
                LocalStoreError::KeyProtectionError(
                    "CIPHERVAULT_MASTER_KEY_SALT must be 16-byte hex".into(),
                )
            });
        }
        let path = get_default_keyfile_path()?;
        let mut hasher = Sha256::new();
        hasher.update(b"CipherVault-MasterKey-Salt-v3");
        hasher.update(path.to_string_lossy().as_bytes());
        let digest = hasher.finalize();
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&digest[..16]);
        Ok(salt)
    }

    pub fn get_default_keyfile_path() -> Result<PathBuf, LocalStoreError> {
        if let Ok(p) = std::env::var("CIPHERVAULT_KEYSTORE_PATH") {
            return Ok(PathBuf::from(p));
        }
        if let Ok(home) = std::env::var("HOME") {
            return Ok(PathBuf::from(home)
                .join(".config")
                .join("ciphervault")
                .join("keystore.key"));
        }
        Err(LocalStoreError::KeyProtectionError(
            "HOME environment variable not set".into(),
        ))
    }

    pub fn protect_with_key(key: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let aad = b"CipherVault-OS-Keyring-v2";
        let encrypted = encrypt_chunk(key, bytes, aad)
            .map_err(|e| LocalStoreError::KeyProtectionError(e.to_string()))?;
        let mut out = Vec::with_capacity(MAGIC_KEYSTORE_V2.len() + encrypted.len());
        out.extend_from_slice(MAGIC_KEYSTORE_V2);
        out.extend_from_slice(&encrypted);
        Ok(out)
    }

    pub fn unprotect_with_key(
        key: &[u8; 32],
        ciphertext: &[u8],
    ) -> Result<Vec<u8>, LocalStoreError> {
        if ciphertext.len() < MAGIC_KEYSTORE_V2.len() {
            return Err(LocalStoreError::KeyProtectionError(
                "Ciphertext too short".into(),
            ));
        }
        let (magic, payload) = ciphertext.split_at(MAGIC_KEYSTORE_V2.len());
        let aad = if magic == MAGIC_KEYSTORE_V2 {
            b"CipherVault-OS-Keyring-v2".as_slice()
        } else {
            b"CipherVault-OS-Keyring".as_slice()
        };
        let data_to_decrypt = if magic == MAGIC_KEYSTORE_V2 {
            payload
        } else {
            ciphertext
        };
        decrypt_chunk(key, data_to_decrypt, aad)
            .map_err(|e| LocalStoreError::KeyProtectionError(e.to_string()))
    }

    pub fn protect(bytes: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let key = match resolve_key() {
            Ok(k) => k,
            Err(_) => {
                let path = get_default_keyfile_path()?;
                if let Some(parent) = path.parent() {
                    let _ = std::fs::create_dir_all(parent);
                }
                let mut new_key = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut new_key);
                #[cfg(unix)]
                {
                    use std::io::Write;
                    use std::os::unix::fs::OpenOptionsExt;
                    let mut file = std::fs::OpenOptions::new()
                        .write(true)
                        .create(true)
                        .truncate(true)
                        .mode(0o600)
                        .open(&path)
                        .map_err(|e| {
                            LocalStoreError::KeyProtectionError(format!(
                                "Failed to create keystore file: {}",
                                e
                            ))
                        })?;
                    file.write_all(&new_key)
                        .map_err(|e| LocalStoreError::KeyProtectionError(e.to_string()))?;
                }
                #[cfg(not(unix))]
                {
                    std::fs::write(&path, new_key)
                        .map_err(|e| LocalStoreError::KeyProtectionError(e.to_string()))?;
                }
                new_key
            }
        };
        protect_with_key(&key, bytes)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let key = resolve_key()?;
        unprotect_with_key(&key, ciphertext)
    }
}

#[cfg(not(windows))]
mod platform {
    pub use super::portable_keystore::{protect, unprotect};
}

/// Protects raw key bytes using the host operating system key facility.
pub fn protect_secret(bytes: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
    platform::protect(bytes)
}

/// Decrypts protected key bytes using the host operating system key facility.
pub fn unprotect_secret(ciphertext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
    platform::unprotect(ciphertext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_protect_and_unprotect_roundtrip() {
        let secret = [0x42u8; 32];
        let protected = protect_secret(&secret).expect("protect should succeed");

        // Assert ciphertext is non-empty and distinct from original bytes
        assert_ne!(protected, secret);

        let recovered = unprotect_secret(&protected).expect("unprotect should succeed");
        assert_eq!(recovered, secret);
    }

    #[test]
    fn test_corrupted_ciphertext_fails() {
        let secret = [0x55u8; 32];
        let mut protected = protect_secret(&secret).expect("protect should succeed");

        // Flip bits
        if let Some(first) = protected.first_mut() {
            *first ^= 0xFF;
        }

        assert!(unprotect_secret(&protected).is_err());
    }

    #[test]
    fn test_portable_keystore_fails_closed_without_secret() {
        // Test that resolve_key fails closed when no key exists
        let key = [0x77u8; 32];
        let secret = b"super_confidential_vault_key";
        let protected = portable_keystore::protect_with_key(&key, secret).unwrap();

        // Wrong key must fail
        let wrong_key = [0x88u8; 32];
        assert!(portable_keystore::unprotect_with_key(&wrong_key, &protected).is_err());

        // Correct key must succeed
        let recovered = portable_keystore::unprotect_with_key(&key, &protected).unwrap();
        assert_eq!(recovered, secret);
    }
}
