use ed25519_dalek::SigningKey as Ed25519SigningKey;
use rand::RngCore;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::CryptoError;
use crate::kdf::{
    derive_subkey, CTX_MANIFEST_KEY, CTX_RECOVERY_ENCRYPT, CTX_RECOVERY_LOCATOR,
    CTX_RECOVERY_SIGNING,
};

/// 32-byte offline random root recovery secret R.
/// Zeroized automatically from memory on drop.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct RecoverySecret([u8; 32]);

impl RecoverySecret {
    /// Generates a fresh random 32-byte recovery secret from the OS CSPRNG.
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    /// Constructs from existing raw 32 bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Exposes inner slice for controlled operations.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the recovery Ed25519 signing keypair.
    pub fn derive_recovery_signing_key(&self) -> Result<Ed25519SigningKey, CryptoError> {
        let mut seed = derive_subkey(&self.0, 1, CTX_RECOVERY_SIGNING)?;
        let key = Ed25519SigningKey::from_bytes(&seed);
        seed.zeroize();
        Ok(key)
    }

    /// Derives the recovery X25519 encryption keypair.
    pub fn derive_recovery_encryption_keys(&self) -> Result<(X25519StaticSecret, X25519PublicKey), CryptoError> {
        let mut seed = derive_subkey(&self.0, 1, CTX_RECOVERY_ENCRYPT)?;
        let sk = X25519StaticSecret::from(seed);
        let pk = X25519PublicKey::from(&sk);
        seed.zeroize();
        Ok((sk, pk))
    }

    /// Derives the opaque recovery locator used to index records at storage operators.
    pub fn derive_recovery_locator(&self) -> Result<[u8; 32], CryptoError> {
        derive_subkey(&self.0, 1, CTX_RECOVERY_LOCATOR)
    }
}

/// 32-byte random vault epoch key V_e.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct VaultEpochKey([u8; 32]);

impl VaultEpochKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Derives the manifest encryption key for this epoch.
    pub fn derive_manifest_key(&self, epoch: u64) -> Result<[u8; 32], CryptoError> {
        derive_subkey(&self.0, epoch, CTX_MANIFEST_KEY)
    }
}

/// 32-byte random per-file-version encryption key.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct FileVersionKey([u8; 32]);

impl FileVersionKey {
    pub fn generate() -> Self {
        let mut bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut bytes);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_hierarchy_derivation() {
        let r = RecoverySecret::generate();
        let _signing_key = r.derive_recovery_signing_key().unwrap();
        let (_enc_sk, enc_pk) = r.derive_recovery_encryption_keys().unwrap();
        let locator = r.derive_recovery_locator().unwrap();

        assert_eq!(enc_pk.as_bytes().len(), 32);
        assert_eq!(locator.len(), 32);

        let epoch_key = VaultEpochKey::generate();
        let manifest_key = epoch_key.derive_manifest_key(1).unwrap();
        assert_eq!(manifest_key.len(), 32);
    }

    #[test]
    fn test_zeroize_memory_scrubbing() {
        let mut secret = RecoverySecret::generate();
        assert_ne!(secret.as_bytes(), &[0u8; 32]);
        secret.zeroize();
        assert_eq!(secret.as_bytes(), &[0u8; 32]);

        let mut epoch_key = VaultEpochKey::generate();
        assert_ne!(epoch_key.as_bytes(), &[0u8; 32]);
        epoch_key.zeroize();
        assert_eq!(epoch_key.as_bytes(), &[0u8; 32]);

        let mut file_key = FileVersionKey::generate();
        assert_ne!(file_key.as_bytes(), &[0u8; 32]);
        file_key.zeroize();
        assert_eq!(file_key.as_bytes(), &[0u8; 32]);
    }
}

