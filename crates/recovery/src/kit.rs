use chrono::Utc;
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use ciphervault_crypto::{open_sealed_box, RecoverySecret, VaultEpochKey};
use ciphervault_format::EpochEnvelope;

use crate::error::RecoveryError;

/// Offline recovery kit containing the master recovery secret R and essential bootstrap descriptors.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct OfflineRecoveryKit {
    pub version: u32,
    pub vault_id_hex: String,
    pub recovery_secret_hex: String,
    pub checksum: u32,
    pub recovery_signing_pk_hex: String,
    pub recovery_encryption_pk_hex: String,
    pub recovery_locator_hex: String,
    pub operator_endpoints: Vec<String>,
    pub created_at_utc: u64,
}

impl OfflineRecoveryKit {
    /// Creates a new offline recovery kit from a master recovery secret.
    pub fn create(
        vault_id: &[u8; 32],
        secret: &RecoverySecret,
        operator_endpoints: Vec<String>,
    ) -> Result<Self, RecoveryError> {
        let signing_key = secret.derive_recovery_signing_key()?;
        let (_, enc_pk) = secret.derive_recovery_encryption_keys()?;
        let locator = secret.derive_recovery_locator()?;

        let mut hasher = Hasher::new();
        hasher.update(secret.as_bytes());
        let checksum = hasher.finalize();

        Ok(Self {
            version: 1,
            vault_id_hex: hex::encode(vault_id),
            recovery_secret_hex: hex::encode(secret.as_bytes()),
            checksum,
            recovery_signing_pk_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            recovery_encryption_pk_hex: hex::encode(enc_pk.as_bytes()),
            recovery_locator_hex: hex::encode(locator),
            operator_endpoints,
            created_at_utc: Utc::now().timestamp() as u64,
        })
    }

    /// Verifies the checksum and extracts the zeroized RecoverySecret.
    pub fn validate_and_extract_secret(&self) -> Result<RecoverySecret, RecoveryError> {
        let mut raw_bytes = hex::decode(&self.recovery_secret_hex)?;
        if raw_bytes.len() != 32 {
            raw_bytes.zeroize();
            return Err(RecoveryError::InvalidKeyLength(raw_bytes.len()));
        }

        let mut hasher = Hasher::new();
        hasher.update(&raw_bytes);
        let calculated = hasher.finalize();

        if calculated != self.checksum {
            raw_bytes.zeroize();
            return Err(RecoveryError::ChecksumMismatch {
                expected: self.checksum,
                calculated,
            });
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_bytes);
        raw_bytes.zeroize();
        let secret = RecoverySecret::from_bytes(arr);
        arr.zeroize();
        Ok(secret)
    }

    /// Generates a clean, human-readable printable text sheet with safety warnings.
    pub fn format_printable(&self) -> String {
        format!(
            r#"================================================================================
                    CIPHERVAULT — EMERGENCY OFFLINE RECOVERY KIT
================================================================================
CRITICAL: Store this document in TWO physically separate, secure locations.
Do NOT commit this to Git, upload to cloud storage, or store only on one laptop.
Loss of this secret means permanent, unrecoverable loss of your encrypted vault.
================================================================================

Vault ID:              {}
Creation Date (UTC):   {}

MASTER RECOVERY SECRET R:
{}

Checksum (CRC32):      {:#010x}

--------------------------------------------------------------------------------
PUBLIC / BOOTSTRAP DESCRIPTORS (Not Secret)
--------------------------------------------------------------------------------
Recovery Signing PK:   {}
Recovery Encrypt PK:   {}
Recovery Locator:      {}

Configured Operators:
{}
================================================================================
"#,
            self.vault_id_hex,
            self.created_at_utc,
            self.recovery_secret_hex,
            self.checksum,
            self.recovery_signing_pk_hex,
            self.recovery_encryption_pk_hex,
            self.recovery_locator_hex,
            self.operator_endpoints
                .iter()
                .map(|e| format!("  - {}", e))
                .collect::<Vec<_>>()
                .join("\n")
        )
    }

    /// Opens an epoch envelope using the master recovery secret.
    pub fn open_envelope(&self, envelope: &EpochEnvelope) -> Result<VaultEpochKey, RecoveryError> {
        let secret = self.validate_and_extract_secret()?;
        let (enc_sk, enc_pk) = secret.derive_recovery_encryption_keys()?;

        let raw_key = open_sealed_box(&enc_sk, &enc_pk, &envelope.sealed_epoch_key)?;
        if raw_key.len() != 32 {
            return Err(RecoveryError::InvalidKeyLength(raw_key.len()));
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_key);
        Ok(VaultEpochKey::from_bytes(arr))
    }

    /// Parses an OfflineRecoveryKit from its printable text representation.
    pub fn parse_from_printable(text: &str) -> Result<Self, RecoveryError> {
        let mut vault_id_hex = String::new();
        let mut recovery_secret_hex = String::new();
        let mut checksum = 0u32;
        let mut recovery_signing_pk_hex = String::new();
        let mut recovery_encryption_pk_hex = String::new();
        let mut recovery_locator_hex = String::new();
        let mut operator_endpoints = Vec::new();
        let mut created_at_utc = 0u64;

        let lines: Vec<&str> = text.lines().map(|l| l.trim()).collect();
        let mut i = 0;
        while i < lines.len() {
            let line = lines[i];
            if line.starts_with("Vault ID:") {
                vault_id_hex = line.trim_start_matches("Vault ID:").trim().to_string();
            } else if line.starts_with("Creation Date (UTC):") {
                created_at_utc = line
                    .trim_start_matches("Creation Date (UTC):")
                    .trim()
                    .parse()
                    .unwrap_or(0);
            } else if line.starts_with("MASTER RECOVERY SECRET R:") {
                if i + 1 < lines.len() {
                    recovery_secret_hex = lines[i + 1].trim().to_string();
                    i += 1;
                }
            } else if line.starts_with("Checksum (CRC32):") {
                let val_str = line.trim_start_matches("Checksum (CRC32):").trim();
                let clean_hex = val_str.trim_start_matches("0x");
                checksum = u32::from_str_radix(clean_hex, 16).unwrap_or(0);
            } else if line.starts_with("Recovery Signing PK:") {
                recovery_signing_pk_hex = line
                    .trim_start_matches("Recovery Signing PK:")
                    .trim()
                    .to_string();
            } else if line.starts_with("Recovery Encrypt PK:") {
                recovery_encryption_pk_hex = line
                    .trim_start_matches("Recovery Encrypt PK:")
                    .trim()
                    .to_string();
            } else if line.starts_with("Recovery Locator:") {
                recovery_locator_hex = line
                    .trim_start_matches("Recovery Locator:")
                    .trim()
                    .to_string();
            } else if line.starts_with("- http://") || line.starts_with("- https://") {
                operator_endpoints.push(line.trim_start_matches("- ").trim().to_string());
            }
            i += 1;
        }

        if recovery_secret_hex.is_empty() || vault_id_hex.is_empty() {
            return Err(RecoveryError::InvalidKitFormat(
                "Missing Vault ID or Recovery Secret in text".into(),
            ));
        }

        let kit = Self {
            version: 1,
            vault_id_hex,
            recovery_secret_hex,
            checksum,
            recovery_signing_pk_hex,
            recovery_encryption_pk_hex,
            recovery_locator_hex,
            operator_endpoints,
            created_at_utc,
        };

        // Validate checksum immediately
        let _ = kit.validate_and_extract_secret()?;
        Ok(kit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, seal_box};

    #[test]
    fn test_recovery_kit_roundtrip_and_checksum() {
        let vault_id = [0x55u8; 32];
        let secret = RecoverySecret::generate();
        let kit =
            OfflineRecoveryKit::create(&vault_id, &secret, vec!["https://op1.example.com".into()])
                .unwrap();

        let extracted = kit.validate_and_extract_secret().unwrap();
        assert_eq!(extracted.as_bytes(), secret.as_bytes());

        // Test printable roundtrip
        let printable = kit.format_printable();
        let parsed = OfflineRecoveryKit::parse_from_printable(&printable).unwrap();
        assert_eq!(parsed.vault_id_hex, kit.vault_id_hex);
        assert_eq!(parsed.recovery_secret_hex, kit.recovery_secret_hex);
        assert_eq!(parsed.checksum, kit.checksum);
        assert_eq!(parsed.operator_endpoints, kit.operator_endpoints);

        // Corrupted secret fails checksum
        let mut bad_kit = kit.clone();
        bad_kit.recovery_secret_hex = hex::encode([0x00u8; 32]);
        assert!(bad_kit.validate_and_extract_secret().is_err());
    }

    #[test]
    fn test_open_epoch_envelope_with_kit() {
        let vault_id = [0x55u8; 32];
        let secret = RecoverySecret::generate();
        let (_, enc_pk) = secret.derive_recovery_encryption_keys().unwrap();
        let kit = OfflineRecoveryKit::create(&vault_id, &secret, vec![]).unwrap();

        let epoch_key = VaultEpochKey::generate();
        let sealed = seal_box(&enc_pk, epoch_key.as_bytes()).unwrap();

        let dev_sk = generate_signing_key();
        let mut envelope = EpochEnvelope {
            version: 1,
            vault_id: vault_id.to_vec(),
            epoch: 1,
            recipient_fingerprint: enc_pk.as_bytes().to_vec(),
            sealed_epoch_key: sealed,
            created_at_utc: 1234,
            signer_device_id: vec![0u8; 32],
            signature: Vec::new(),
        };
        envelope.sign(&dev_sk).unwrap();

        let recovered_epoch_key = kit.open_envelope(&envelope).unwrap();
        assert_eq!(recovered_epoch_key.as_bytes(), epoch_key.as_bytes());
    }
}
