//! Scoped envelope encryption (Phase 5, T-501/T-502).
//!
//! Every secret version gets a fresh random Data Encryption Key (DEK).
//! Values are sealed with XChaCha20-Poly1305 under the DEK with scope-bound
//! AAD (`tenant ‖ project ‖ environment ‖ secret ‖ version`), so ciphertext
//! copied across scopes fails verification. DEKs are wrapped by a
//! Key-Encryption Key through a [`KeyWrappingService`] (local XChaCha KEK for
//! development and small deployments; KMS/HSM providers plug in here once
//! provider dependencies are available).

use rand::RngCore;
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::aead::{decrypt_with_nonce, encrypt_with_nonce, KEY_SIZE, NONCE_SIZE, TAG_SIZE};
use crate::error::CryptoError;

/// Domain separator for scoped secret-value AAD.
pub const SCOPE_AAD_DOMAIN: &[u8] = b"CipherVault-ScopeAAD-v1";
/// Domain separator for local KEK-wrap AAD.
pub const KEK_WRAP_DOMAIN: &[u8] = b"cv-kek-wrap-v1";

/// Builds scope-bound AAD: `domain ‖ tenant16 ‖ project16 ‖ env16 ‖
/// secret16 ‖ version_be32` (90 bytes). Identifiers are raw 16-byte scope
/// ids; fixed widths keep the encoding unambiguous.
pub fn scope_aad(
    tenant_id: &[u8; 16],
    project_id: &[u8; 16],
    environment_id: &[u8; 16],
    secret_id: &[u8; 16],
    version: u32,
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(SCOPE_AAD_DOMAIN.len() + 64 + 4);
    aad.extend_from_slice(SCOPE_AAD_DOMAIN);
    aad.extend_from_slice(tenant_id);
    aad.extend_from_slice(project_id);
    aad.extend_from_slice(environment_id);
    aad.extend_from_slice(secret_id);
    aad.extend_from_slice(&version.to_be_bytes());
    aad
}

/// Fresh random per-version Data Encryption Key. Zeroized on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct DataEncryptionKey([u8; KEY_SIZE]);

impl DataEncryptionKey {
    /// Generates a fresh random DEK from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; KEY_SIZE];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs from existing raw 32 bytes.
    pub fn from_bytes(bytes: [u8; KEY_SIZE]) -> Self {
        Self(bytes)
    }

    /// Exposes inner bytes for controlled operations.
    pub fn as_bytes(&self) -> &[u8; KEY_SIZE] {
        &self.0
    }
}

/// Sealed value with detached nonce (mirrors the `secret_versions` columns).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSecret {
    pub nonce: [u8; NONCE_SIZE],
    pub ciphertext: Vec<u8>,
}

/// Seals plaintext under a DEK with scope-bound AAD and a fresh random nonce.
pub fn seal_secret_value(
    dek: &DataEncryptionKey,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedSecret, CryptoError> {
    let mut nonce = [0u8; NONCE_SIZE];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ciphertext = encrypt_with_nonce(dek.as_bytes(), &nonce, plaintext, aad)?;
    Ok(SealedSecret { nonce, ciphertext })
}

/// Opens a sealed value. Short payloads, wrong DEKs, and wrong AAD all fail
/// closed with [`CryptoError::AuthTagVerificationFailed`] (no oracle).
pub fn open_secret_value(
    dek: &DataEncryptionKey,
    sealed: &SealedSecret,
    aad: &[u8],
) -> Result<Vec<u8>, CryptoError> {
    if sealed.ciphertext.len() < TAG_SIZE {
        return Err(CryptoError::AuthTagVerificationFailed);
    }
    decrypt_with_nonce(dek.as_bytes(), &sealed.nonce, &sealed.ciphertext, aad)
}

/// Key-wrapping backend. KMS/HSM providers implement this trait; rotation
/// and audit live with the implementation.
pub trait KeyWrappingService {
    /// Wraps a DEK, returning the wrapped blob bound to `kek_id`.
    fn wrap_dek(&self, dek: &DataEncryptionKey) -> Result<WrappedDek, CryptoError>;
    /// Unwraps a DEK, refusing blobs minted for another KEK id.
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<DataEncryptionKey, CryptoError>;
}

/// Wrapped DEK with detached nonce (mirrors `encryption_keys.wrapped_key`
/// plus the KEK reference).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedDek {
    pub kek_id: String,
    pub nonce: [u8; NONCE_SIZE],
    pub blob: Vec<u8>,
}

/// Local XChaCha Key-Encryption-Key service for development and small
/// deployments. Production multi-tenant deployments must use a KMS/HSM
/// implementation of [`KeyWrappingService`] instead.
pub struct LocalKekService {
    kek_id: String,
    kek: [u8; KEY_SIZE],
}

impl LocalKekService {
    /// Binds a raw 32-byte KEK to its identifier.
    pub fn new(kek_id: &str, kek: [u8; KEY_SIZE]) -> Self {
        Self {
            kek_id: kek_id.to_string(),
            kek,
        }
    }

    fn wrap_aad(&self) -> Vec<u8> {
        [KEK_WRAP_DOMAIN, self.kek_id.as_bytes()].concat()
    }
}

impl KeyWrappingService for LocalKekService {
    fn wrap_dek(&self, dek: &DataEncryptionKey) -> Result<WrappedDek, CryptoError> {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::thread_rng().fill_bytes(&mut nonce);
        let blob = encrypt_with_nonce(&self.kek, &nonce, dek.as_bytes(), &self.wrap_aad())?;
        Ok(WrappedDek {
            kek_id: self.kek_id.clone(),
            nonce,
            blob,
        })
    }

    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<DataEncryptionKey, CryptoError> {
        if wrapped.kek_id != self.kek_id {
            return Err(CryptoError::AuthTagVerificationFailed);
        }
        if wrapped.blob.len() < TAG_SIZE {
            return Err(CryptoError::AuthTagVerificationFailed);
        }
        let raw = decrypt_with_nonce(&self.kek, &wrapped.nonce, &wrapped.blob, &self.wrap_aad())?;
        let bytes: [u8; KEY_SIZE] =
            raw.try_into()
                .map_err(|raw: Vec<u8>| CryptoError::InvalidKeyLength {
                    expected: KEY_SIZE,
                    actual: raw.len(),
                })?;
        Ok(DataEncryptionKey::from_bytes(bytes))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids() -> ([u8; 16], [u8; 16], [u8; 16], [u8; 16]) {
        ([0x01; 16], [0x02; 16], [0x03; 16], [0x04; 16])
    }

    #[test]
    fn scope_aad_layout_is_fixed_and_unambiguous() {
        let (tenant, project, env, secret) = ids();
        let aad = scope_aad(&tenant, &project, &env, &secret, 7);
        assert_eq!(aad.len(), SCOPE_AAD_DOMAIN.len() + 64 + 4);
        assert_eq!(&aad[..SCOPE_AAD_DOMAIN.len()], SCOPE_AAD_DOMAIN);
        assert_eq!(&aad[aad.len() - 4..], &7u32.to_be_bytes());
        // Every field perturbs the output.
        let flip = |aad: Vec<u8>| aad;
        assert_ne!(
            flip(aad.clone()),
            scope_aad(&[0x11; 16], &project, &env, &secret, 7)
        );
        assert_ne!(aad, scope_aad(&tenant, &[0x12; 16], &env, &secret, 7));
        assert_ne!(aad, scope_aad(&tenant, &project, &[0x13; 16], &secret, 7));
        assert_ne!(aad, scope_aad(&tenant, &project, &env, &[0x14; 16], 7));
        assert_ne!(aad, scope_aad(&tenant, &project, &env, &secret, 8));
    }

    #[test]
    fn seal_open_roundtrip_and_cross_scope_replay_fails() {
        let (tenant, project, env, secret) = ids();
        let dek = DataEncryptionKey::generate();
        let aad = scope_aad(&tenant, &project, &env, &secret, 1);
        let sealed = seal_secret_value(&dek, b"plaintext-canary", &aad).unwrap();
        assert_eq!(
            open_secret_value(&dek, &sealed, &aad).unwrap(),
            b"plaintext-canary"
        );
        // Same ciphertext under another scope's AAD must fail.
        let other_aad = scope_aad(&tenant, &project, &[0x99; 16], &secret, 1);
        assert!(open_secret_value(&dek, &sealed, &other_aad).is_err());
        // Tampered ciphertext and wrong DEK fail.
        let mut tampered = sealed.clone();
        tampered.ciphertext[0] ^= 0x01;
        assert!(open_secret_value(&dek, &tampered, &aad).is_err());
        assert!(open_secret_value(&DataEncryptionKey::generate(), &sealed, &aad).is_err());
        // Short payload fails closed (no panic, no oracle).
        let short = SealedSecret {
            nonce: sealed.nonce,
            ciphertext: vec![0u8; TAG_SIZE - 1],
        };
        assert!(open_secret_value(&dek, &short, &aad).is_err());
    }

    #[test]
    fn wrap_unwrap_roundtrip_and_kek_mismatch_fails() {
        let service = LocalKekService::new("kek-p1", [0x33; KEY_SIZE]);
        let dek = DataEncryptionKey::generate();
        let wrapped = service.wrap_dek(&dek).unwrap();
        assert_eq!(wrapped.kek_id, "kek-p1");
        let back = service.unwrap_dek(&wrapped).unwrap();
        assert_eq!(back.as_bytes(), dek.as_bytes());
        // Another KEK instance refuses the blob.
        let other = LocalKekService::new("kek-p1", [0x34; KEY_SIZE]);
        assert!(other.unwrap_dek(&wrapped).is_err());
        // Another KEK id refuses the blob.
        let renamed = LocalKekService::new("kek-p2", [0x33; KEY_SIZE]);
        assert!(renamed.unwrap_dek(&wrapped).is_err());
        // Tampered blob fails.
        let mut tampered = wrapped;
        tampered.blob[0] ^= 0x01;
        assert!(service.unwrap_dek(&tampered).is_err());
    }

    #[test]
    fn dek_explicit_zeroize_scrubs() {
        let mut dek = DataEncryptionKey::from_bytes([0x55; KEY_SIZE]);
        dek.zeroize();
        assert!(dek.as_bytes().iter().all(|byte| *byte == 0));
    }
}
