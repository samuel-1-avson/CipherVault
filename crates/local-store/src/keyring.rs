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
            use zeroize::Zeroize;
            std::slice::from_raw_parts_mut(out_blob.pb_data, out_blob.cb_data as usize).zeroize();
            LocalFree(out_blob.pb_data as *mut _);
        }

        Ok(out_bytes)
    }
}

pub mod portable_keystore {
    use super::*;
    use ciphervault_crypto::{decrypt_chunk, encrypt_chunk};
    use sha2::{Digest, Sha256};
    use std::io::Write;
    use std::path::Path;
    use std::path::PathBuf;
    use zeroize::Zeroizing;

    pub const MAGIC_KEYSTORE_V2: &[u8; 4] = b"CVK2";

    /// Resolves the master encryption key for the portable keystore.
    /// Fails closed if neither an explicit env var nor a valid key file exists.
    pub fn resolve_key() -> Result<[u8; 32], LocalStoreError> {
        // 1. Check CIPHERVAULT_MASTER_KEY env var
        if let Some(value) = std::env::var_os("CIPHERVAULT_MASTER_KEY") {
            let val = value.into_string().map_err(|_| {
                LocalStoreError::KeyProtectionError(
                    "CIPHERVAULT_MASTER_KEY is not valid Unicode".into(),
                )
            })?;
            let val = Zeroizing::new(val);
            let val = val.trim();
            if val.is_empty() {
                return Err(LocalStoreError::KeyProtectionError(
                    "CIPHERVAULT_MASTER_KEY cannot be empty".into(),
                ));
            }
            if let Ok(bytes) = hex::decode(val) {
                let bytes = Zeroizing::new(bytes);
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
        read_key_file(&key_path).map_err(|error| {
            LocalStoreError::KeyProtectionError(format!(
                "Failed to read provisioned keystore at {}: {error}",
                key_path.display()
            ))
        })
    }

    fn read_key_file(path: &Path) -> std::io::Result<[u8; 32]> {
        let metadata = std::fs::symlink_metadata(path)?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(std::io::Error::other(
                "keystore must be a regular, non-symlink file",
            ));
        }
        let mut file = ciphervault_file_lock::open_regular_file(path)?;
        if file.metadata()?.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "keystore key must contain exactly 32 bytes; refusing replacement",
            ));
        }
        let mut content = Zeroizing::new(Vec::with_capacity(32));
        use std::io::Read;
        (&mut file).take(33).read_to_end(&mut content)?;
        if content.len() != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "keystore key must contain exactly 32 bytes; refusing replacement",
            ));
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&content);
        Ok(key)
    }

    /// Provision only a genuinely missing key, never an invalid or inaccessible one.
    /// A complete key is published with an exclusive hard link, so concurrent readers
    /// cannot observe partial bytes and a competing provisioner cannot overwrite it.
    pub fn provision_key_file(path: &Path) -> Result<[u8; 32], LocalStoreError> {
        let result = (|| -> std::io::Result<[u8; 32]> {
            match read_key_file(path) {
                Ok(key) => return Ok(key),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let parent = path.parent().unwrap_or_else(|| Path::new("."));
            std::fs::create_dir_all(parent)?;
            let temporary = parent.join(format!(
                ".keystore-{}-{:032x}",
                std::process::id(),
                rand::random::<u128>()
            ));
            let mut key = Zeroizing::new([0u8; 32]);
            rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, key.as_mut());
            let publication = (|| -> std::io::Result<()> {
                let mut file = ciphervault_file_lock::create_secret_file(&temporary)?;
                file.write_all(key.as_ref())?;
                file.sync_all()?;
                drop(file);
                match std::fs::hard_link(&temporary, path) {
                    Ok(()) => ciphervault_file_lock::sync_directory(parent),
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
                    Err(error) => Err(error),
                }
            })();
            let _ = std::fs::remove_file(&temporary);
            publication?;
            read_key_file(path)
        })();
        result.map_err(|error| {
            LocalStoreError::KeyProtectionError(format!(
                "Keystore provisioning failed at {}: {error}",
                path.display()
            ))
        })
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
        // New keystores (v1.0.31+): a random 16-byte salt persisted
        // beside the keystore (owner-only where the platform supports
        // it). Existing keystores keep the legacy path-derived salt so
        // their passphrases keep working (dual-read by file presence).
        let salt_path = path.with_extension("salt");
        if let Ok(raw) = std::fs::read_to_string(&salt_path) {
            let bytes = hex::decode(raw.trim()).map_err(|_| {
                LocalStoreError::KeyProtectionError("keystore salt file is not hex".into())
            })?;
            return bytes.try_into().map_err(|_| {
                LocalStoreError::KeyProtectionError("keystore salt must be 16 bytes".into())
            });
        }
        if path.exists() {
            // Legacy keystore: keep deriving from the path (compat).
            let mut hasher = Sha256::new();
            hasher.update(b"CipherVault-MasterKey-Salt-v3");
            hasher.update(path.to_string_lossy().as_bytes());
            let digest = hasher.finalize();
            let mut salt = [0u8; 16];
            salt.copy_from_slice(&digest[..16]);
            return Ok(salt);
        }
        // Brand-new keystore: generate + persist a random salt.
        let mut salt = [0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut salt);
        if let Some(parent) = salt_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        std::fs::write(&salt_path, hex::encode(salt)).map_err(|e| {
            LocalStoreError::KeyProtectionError(format!(
                "could not persist keystore salt {}: {e}",
                salt_path.display()
            ))
        })?;
        let _ = ciphervault_file_lock::lock_secret_file(&salt_path);
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
        let key = Zeroizing::new(if std::env::var_os("CIPHERVAULT_MASTER_KEY").is_some() {
            resolve_key()?
        } else {
            provision_key_file(&get_default_keyfile_path()?)?
        });
        protect_with_key(&key, bytes)
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        let key = Zeroizing::new(resolve_key()?);
        unprotect_with_key(&key, ciphertext)
    }
}

#[cfg(not(windows))]
mod os_keyring {
    use super::*;
    use rand::RngCore;
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::sync::Mutex;
    use zeroize::Zeroizing;

    static PROVISION_LOCK: Mutex<()> = Mutex::new(());

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    fn decode_hex_key(raw: &str) -> Option<[u8; 32]> {
        let trimmed = raw.trim();
        let bytes = Zeroizing::new(hex::decode(trimmed).ok()?);
        if bytes.len() != 32 {
            return None;
        }
        let mut key = [0u8; 32];
        key.copy_from_slice(&bytes);
        Some(key)
    }

    pub fn require_strict() -> bool {
        matches!(
            std::env::var("CIPHERVAULT_REQUIRE_OS_KEYRING").as_deref(),
            Ok("1") | Ok("true") | Ok("TRUE")
        )
    }

    #[cfg(target_os = "macos")]
    pub fn backend_name() -> &'static str {
        "macos-keychain"
    }

    #[cfg(target_os = "linux")]
    pub fn backend_name() -> &'static str {
        "linux-secret-service"
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn backend_name() -> &'static str {
        "portable-file-keystore"
    }

    #[cfg(target_os = "macos")]
    pub fn lookup_key() -> Option<[u8; 32]> {
        let output = Command::new("/usr/bin/security")
            .args([
                "find-generic-password",
                "-s",
                "io.ciphervault.local-store",
                "-a",
                "master-key",
                "-w",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = Zeroizing::new(String::from_utf8_lossy(&output.stdout).into_owned());
        decode_hex_key(&stdout)
    }

    #[cfg(target_os = "macos")]
    pub fn store_key(key: &[u8; 32]) -> Result<(), LocalStoreError> {
        let hex_key = Zeroizing::new(hex::encode(key));
        let mut child = Command::new("/usr/bin/security")
            .arg("-i")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                LocalStoreError::KeyProtectionError(format!(
                    "Failed to launch macOS security tool: {e}"
                ))
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            // Omit -U so concurrent process provisioners cannot silently overwrite
            // an already-persisted Keychain item.
            let cmd = Zeroizing::new(format!(
                "add-generic-password -s io.ciphervault.local-store -a master-key -w {}\n",
                hex_key.as_str()
            ));
            stdin.write_all(cmd.as_bytes()).map_err(|e| {
                LocalStoreError::KeyProtectionError(format!(
                    "Failed to write key to macOS security stdin: {e}"
                ))
            })?;
        }
        let out = child.wait_with_output().map_err(|e| {
            LocalStoreError::KeyProtectionError(format!("macOS security wait failed: {e}"))
        })?;
        if !out.status.success() {
            return Err(LocalStoreError::KeyProtectionError(format!(
                "macOS Keychain add-generic-password failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    #[cfg(target_os = "linux")]
    pub fn lookup_key() -> Option<[u8; 32]> {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none_or(|v| v.is_empty()) {
            return None;
        }
        let output = Command::new("secret-tool")
            .args(["lookup", "service", "ciphervault", "account", "master-key"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .output()
            .ok()?;
        if !output.status.success() {
            return None;
        }
        let stdout = Zeroizing::new(String::from_utf8_lossy(&output.stdout).into_owned());
        decode_hex_key(&stdout)
    }

    #[cfg(target_os = "linux")]
    pub fn store_key(key: &[u8; 32]) -> Result<(), LocalStoreError> {
        if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none_or(|v| v.is_empty()) {
            return Err(LocalStoreError::KeyProtectionError(
                "DBUS_SESSION_BUS_ADDRESS not set; Linux Secret Service unavailable".into(),
            ));
        }
        let hex_key = Zeroizing::new(hex::encode(key));
        let mut child = Command::new("secret-tool")
            .args([
                "store",
                "--label=CipherVault Local Keystore",
                "service",
                "ciphervault",
                "account",
                "master-key",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| {
                LocalStoreError::KeyProtectionError(format!("Failed to launch secret-tool: {e}"))
            })?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(hex_key.as_bytes()).map_err(|e| {
                LocalStoreError::KeyProtectionError(format!(
                    "Failed to write key to secret-tool stdin: {e}"
                ))
            })?;
        }
        let out = child.wait_with_output().map_err(|e| {
            LocalStoreError::KeyProtectionError(format!("secret-tool wait failed: {e}"))
        })?;
        if !out.status.success() {
            return Err(LocalStoreError::KeyProtectionError(format!(
                "secret-tool store failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            )));
        }
        Ok(())
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn lookup_key() -> Option<[u8; 32]> {
        None
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    pub fn store_key(_key: &[u8; 32]) -> Result<(), LocalStoreError> {
        Err(LocalStoreError::KeyProtectionError(
            "No native OS keyring backend on this platform".into(),
        ))
    }

    pub fn provision_or_get_key() -> Result<[u8; 32], LocalStoreError> {
        let _guard = PROVISION_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = lookup_key() {
            return Ok(existing);
        }
        let mut generated = Zeroizing::new([0u8; 32]);
        rand::thread_rng().fill_bytes(&mut *generated);
        match store_key(&generated) {
            Ok(()) => {}
            Err(err) => {
                // Another process may have inserted the entry first (e.g. errSecDuplicateItem).
                if let Some(existing) = lookup_key() {
                    return Ok(existing);
                }
                return Err(err);
            }
        }
        // Read-back confirms persistence in the OS keyring rather than a silent no-op.
        lookup_key().ok_or_else(|| {
            LocalStoreError::KeyProtectionError(format!(
                "{} stored key but read-back returned empty",
                backend_name()
            ))
        })
    }
}

#[cfg(not(windows))]
mod platform {
    use super::os_keyring;
    use super::portable_keystore;
    use super::LocalStoreError;
    use zeroize::Zeroizing;

    fn has_explicit_override() -> bool {
        std::env::var_os("CIPHERVAULT_MASTER_KEY").is_some()
            || std::env::var_os("CIPHERVAULT_KEYSTORE_PATH").is_some()
    }

    pub fn active_backend() -> &'static str {
        if std::env::var_os("CIPHERVAULT_MASTER_KEY").is_some() {
            return "env-master-key";
        }
        if std::env::var_os("CIPHERVAULT_KEYSTORE_PATH").is_some() {
            return "file-keystore-override";
        }
        if os_keyring::lookup_key().is_some() {
            return os_keyring::backend_name();
        }
        "portable-file-keystore"
    }

    pub fn protect(bytes: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        if has_explicit_override() {
            return portable_keystore::protect(bytes);
        }
        if let Some(key) = os_keyring::lookup_key() {
            let key = Zeroizing::new(key);
            return portable_keystore::protect_with_key(&key, bytes);
        }
        // Preserve backward compatibility with already-provisioned local file keystores
        // unless strict OS keyring custody is explicitly required.
        let legacy_exists = portable_keystore::get_default_keyfile_path()
            .map(|p| p.exists())
            .unwrap_or(false);
        if legacy_exists && !os_keyring::require_strict() {
            return portable_keystore::protect(bytes);
        }
        match os_keyring::provision_or_get_key() {
            Ok(key) => {
                let key = Zeroizing::new(key);
                portable_keystore::protect_with_key(&key, bytes)
            }
            Err(err) => {
                if os_keyring::require_strict() {
                    return Err(err);
                }
                portable_keystore::protect(bytes)
            }
        }
    }

    pub fn unprotect(ciphertext: &[u8]) -> Result<Vec<u8>, LocalStoreError> {
        if has_explicit_override() {
            return portable_keystore::unprotect(ciphertext);
        }
        if let Some(key) = os_keyring::lookup_key() {
            let key = Zeroizing::new(key);
            if let Ok(plain) = portable_keystore::unprotect_with_key(&key, ciphertext) {
                return Ok(plain);
            }
        }
        if os_keyring::require_strict() {
            return Err(LocalStoreError::KeyProtectionError(format!(
                "CIPHERVAULT_REQUIRE_OS_KEYRING=1 set, but {} could not decrypt key blob",
                os_keyring::backend_name()
            )));
        }
        portable_keystore::unprotect(ciphertext)
    }
}

/// Returns the active OS key-custody backend identifier.
pub fn active_keyring_backend() -> &'static str {
    #[cfg(windows)]
    {
        "windows-dpapi"
    }
    #[cfg(not(windows))]
    {
        platform::active_backend()
    }
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
    fn concurrent_provisioners_all_use_the_same_durable_key() {
        let root =
            std::env::temp_dir().join(format!("cv-key-race-{:032x}", rand::random::<u128>()));
        let path = root.join("master.key");
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(12));
        let threads: Vec<_> = (0..12)
            .map(|_| {
                let path = path.clone();
                let barrier = barrier.clone();
                std::thread::spawn(move || {
                    barrier.wait();
                    portable_keystore::provision_key_file(&path).unwrap()
                })
            })
            .collect();
        let keys: Vec<_> = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect();
        assert!(keys.iter().all(|key| key == &keys[0]));
        assert_eq!(std::fs::read(&path).unwrap(), keys[0]);
        let encrypted = portable_keystore::protect_with_key(&keys[0], b"synthetic secret").unwrap();
        for key in keys {
            assert_eq!(
                portable_keystore::unprotect_with_key(&key, &encrypted).unwrap(),
                b"synthetic secret"
            );
        }
        std::fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn malformed_existing_key_is_never_replaced() {
        let root =
            std::env::temp_dir().join(format!("cv-key-invalid-{:032x}", rand::random::<u128>()));
        std::fs::create_dir_all(&root).unwrap();
        let path = root.join("master.key");
        for bytes in [vec![7; 7], vec![8; 33]] {
            std::fs::write(&path, &bytes).unwrap();
            assert!(portable_keystore::provision_key_file(&path).is_err());
            assert_eq!(std::fs::read(&path).unwrap(), bytes);
        }
        std::fs::remove_file(&path).unwrap();
        std::fs::create_dir(&path).unwrap();
        assert!(portable_keystore::provision_key_file(&path).is_err());
        assert!(path.is_dir());
        std::fs::remove_dir_all(root).unwrap();
    }

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

    #[test]
    fn active_keyring_backend_reports_known_identifier() {
        let backend = active_keyring_backend();
        assert!([
            "windows-dpapi",
            "env-master-key",
            "file-keystore-override",
            "macos-keychain",
            "linux-secret-service",
            "portable-file-keystore",
        ]
        .contains(&backend));
    }
}
