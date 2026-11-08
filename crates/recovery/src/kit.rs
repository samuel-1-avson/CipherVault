use chrono::Utc;
use crc32fast::Hasher;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use ciphervault_crypto::{open_sealed_box, RecoverySecret, VaultEpochKey};
use ciphervault_format::EpochEnvelope;

use crate::error::RecoveryError;

/// Offline recovery kit containing the master recovery secret R and essential bootstrap descriptors.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct OfflineRecoveryKit {
    pub version: u32,
    pub vault_id_hex: String,
    pub recovery_secret_hex: String,
    pub checksum: u32,
    /// SHA-256 (truncated, hex) over the secret + descriptors, added in
    /// v1.0.31. `None` on kits written by older versions; verification
    /// falls back to the legacy CRC32 `checksum` for those, and always
    /// re-derives the public descriptors from the secret itself.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum_v2: Option<String>,
    pub recovery_signing_pk_hex: String,
    pub recovery_encryption_pk_hex: String,
    pub recovery_locator_hex: String,
    pub operator_endpoints: Vec<String>,
    pub created_at_utc: u64,
}
impl Drop for OfflineRecoveryKit {
    fn drop(&mut self) {
        self.recovery_secret_hex.zeroize();
    }
}

impl std::fmt::Debug for OfflineRecoveryKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OfflineRecoveryKit")
            .field("version", &self.version)
            .field("vault_id_hex", &self.vault_id_hex)
            .field("recovery_secret_hex", &"[REDACTED_SECRET]")
            .field("checksum", &self.checksum)
            .field("recovery_signing_pk_hex", &self.recovery_signing_pk_hex)
            .field(
                "recovery_encryption_pk_hex",
                &self.recovery_encryption_pk_hex,
            )
            .field("recovery_locator_hex", &self.recovery_locator_hex)
            .field("operator_endpoints", &self.operator_endpoints)
            .field("created_at_utc", &self.created_at_utc)
            .finish()
    }
}

/// Stronger kit integrity check (v1.0.31+): first 16 bytes of
/// SHA-256("CipherVault-KitChecksum-v2" || secret || vault_id_hex),
/// hex-encoded. CRC32 stays for backward compatibility with old kits;
/// descriptor re-derivation in `validate_and_extract_secret` remains
/// the authoritative check for both generations.
fn kit_checksum_v2(secret_bytes: &[u8; 32], vault_id_hex: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"CipherVault-KitChecksum-v2");
    hasher.update(secret_bytes);
    hasher.update(vault_id_hex.as_bytes());
    hex::encode(&hasher.finalize()[..16])
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
        let checksum_v2 = Some(kit_checksum_v2(secret.as_bytes(), &hex::encode(vault_id)));

        Ok(Self {
            version: 1,
            vault_id_hex: hex::encode(vault_id),
            recovery_secret_hex: hex::encode(secret.as_bytes()),
            checksum,
            checksum_v2,
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
        if let Some(expected_v2) = &self.checksum_v2 {
            let mut arr2 = [0u8; 32];
            arr2.copy_from_slice(&raw_bytes);
            let actual_v2 = kit_checksum_v2(&arr2, &self.vault_id_hex);
            arr2.zeroize();
            if !actual_v2.eq_ignore_ascii_case(expected_v2) {
                raw_bytes.zeroize();
                return Err(RecoveryError::InvalidKitFormat(
                    "Recovery kit v2 checksum mismatch".into(),
                ));
            }
        }

        let mut arr = [0u8; 32];
        arr.copy_from_slice(&raw_bytes);
        raw_bytes.zeroize();
        let secret = RecoverySecret::from_bytes(arr);
        arr.zeroize();
        let signing = secret.derive_recovery_signing_key()?;
        let (_, encryption) = secret.derive_recovery_encryption_keys()?;
        if self.version != 1
            || hex::decode(&self.vault_id_hex)?.len() != 32
            || !self
                .recovery_signing_pk_hex
                .eq_ignore_ascii_case(&hex::encode(signing.verifying_key().as_bytes()))
            || !self
                .recovery_encryption_pk_hex
                .eq_ignore_ascii_case(&hex::encode(encryption.as_bytes()))
            || !self
                .recovery_locator_hex
                .eq_ignore_ascii_case(&hex::encode(secret.derive_recovery_locator()?))
        {
            return Err(RecoveryError::InvalidKitFormat(
                "Recovery kit public descriptors do not match its secret".into(),
            ));
        }
        Ok(secret)
    }

    /// Groups a 64-hex secret as 8×8 for hand transcription. Spaces are
    /// cosmetic: the parser strips all non-hex characters.
    fn grouped_secret_hex(&self) -> String {
        self.recovery_secret_hex
            .as_bytes()
            .chunks(8)
            .map(|c| String::from_utf8_lossy(c).into_owned())
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn human_created_at(&self) -> String {
        chrono::DateTime::from_timestamp(self.created_at_utc as i64, 0)
            .map(|dt| dt.format("%Y-%m-%d %H:%M UTC").to_string())
            .unwrap_or_else(|| format!("{} (unix epoch)", self.created_at_utc))
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
Creation Date (UTC):   {} ({})

MASTER RECOVERY SECRET R (copy exactly; spaces are optional):
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
            self.human_created_at(),
            self.grouped_secret_hex(),
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

        if envelope.vault_id != hex::decode(&self.vault_id_hex)?
            || envelope.recipient_fingerprint != enc_pk.as_bytes()
        {
            return Err(RecoveryError::InvalidKitFormat(
                "Epoch envelope vault/recipient mismatch".into(),
            ));
        }
        let raw_key = Zeroizing::new(open_sealed_box(
            &enc_sk,
            &enc_pk,
            &envelope.sealed_epoch_key,
        )?);
        if raw_key.len() != 32 {
            return Err(RecoveryError::InvalidKeyLength(raw_key.len()));
        }

        let mut arr = Zeroizing::new([0u8; 32]);
        arr.copy_from_slice(&raw_key);
        Ok(VaultEpochKey::from_bytes(*arr))
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
        // U-H5: hand copies wrap lines, add spaces/dashes, or drop the
        // endpoint scheme. Strip everything that isn't hex for secrets and
        // accept scheme-less endpoints.
        let clean_hex =
            |s: &str| -> String { s.chars().filter(|c| c.is_ascii_hexdigit()).collect() };
        while i < lines.len() {
            let line = lines[i];
            if line.starts_with("Vault ID:") {
                vault_id_hex = clean_hex(line.trim_start_matches("Vault ID:"));
            } else if line.starts_with("Creation Date (UTC):") {
                // Accepts both the bare epoch and "epoch (human date)".
                let rest = line.trim_start_matches("Creation Date (UTC):").trim();
                let epoch_part = rest.split_whitespace().next().unwrap_or("");
                created_at_utc = epoch_part.parse().unwrap_or(0);
            } else if line.starts_with("MASTER RECOVERY SECRET R") {
                // Accumulate wrapped continuation lines until 64 hex chars.
                let mut acc = String::new();
                let mut j = i + 1;
                while j < lines.len() && acc.len() < 64 {
                    let next = lines[j];
                    if next.is_empty()
                        || next.contains(':')
                        || next.starts_with('=')
                        || next.starts_with('-')
                    {
                        break;
                    }
                    acc.push_str(&clean_hex(next));
                    j += 1;
                }
                if acc.len() != 64 {
                    return Err(RecoveryError::InvalidKitFormat(format!(
                        "Recovery secret must be 64 hex characters, found {} — check for missing or extra characters",
                        acc.len()
                    )));
                }
                recovery_secret_hex = acc;
                i = j - 1;
            } else if line.starts_with("Checksum (CRC32):") {
                let val_str = line.trim_start_matches("Checksum (CRC32):").trim();
                let clean = clean_hex(val_str.trim_start_matches("0x"));
                checksum = u32::from_str_radix(&clean, 16).unwrap_or(0);
            } else if line.starts_with("Recovery Signing PK:") {
                recovery_signing_pk_hex =
                    clean_hex(line.trim_start_matches("Recovery Signing PK:"));
            } else if line.starts_with("Recovery Encrypt PK:") {
                recovery_encryption_pk_hex =
                    clean_hex(line.trim_start_matches("Recovery Encrypt PK:"));
            } else if line.starts_with("Recovery Locator:") {
                recovery_locator_hex = clean_hex(line.trim_start_matches("Recovery Locator:"));
            } else if let Some(rest) = line.strip_prefix("- ") {
                // Operator lines: printed as "- <endpoint>"; tolerate a
                // hand-copied endpoint missing its scheme.
                let endpoint = rest.trim();
                if !endpoint.is_empty()
                    && (endpoint.contains('.')
                        || endpoint.contains(':')
                        || endpoint.starts_with("http"))
                {
                    operator_endpoints.push(endpoint.to_string());
                }
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
            checksum_v2: None,
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

/// Individual guardian threshold recovery share kit.
#[derive(Serialize, Deserialize, Clone, PartialEq)]
pub struct ThresholdRecoveryKit {
    pub version: u32,
    pub vault_id_hex: String,
    pub guardian_index: u8,
    pub threshold: u8,
    pub total_shares: u8,
    pub share_data_hex: String,
    pub checksum: u32,
    pub recovery_signing_pk_hex: String,
    pub recovery_encryption_pk_hex: String,
    pub recovery_locator_hex: String,
    pub operator_endpoints: Vec<String>,
    pub created_at_utc: u64,
}
impl Drop for ThresholdRecoveryKit {
    fn drop(&mut self) {
        self.share_data_hex.zeroize();
    }
}

impl std::fmt::Debug for ThresholdRecoveryKit {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThresholdRecoveryKit")
            .field("version", &self.version)
            .field("vault_id_hex", &self.vault_id_hex)
            .field("guardian_index", &self.guardian_index)
            .field("threshold", &self.threshold)
            .field("total_shares", &self.total_shares)
            .field("share_data_hex", &"[REDACTED_SHARE]")
            .field("checksum", &self.checksum)
            .field("recovery_signing_pk_hex", &self.recovery_signing_pk_hex)
            .field(
                "recovery_encryption_pk_hex",
                &self.recovery_encryption_pk_hex,
            )
            .field("recovery_locator_hex", &self.recovery_locator_hex)
            .field("operator_endpoints", &self.operator_endpoints)
            .field("created_at_utc", &self.created_at_utc)
            .finish()
    }
}

impl ThresholdRecoveryKit {
    /// Splits an existing OfflineRecoveryKit into N guardian threshold recovery shares.
    pub fn split_kit(
        kit: &OfflineRecoveryKit,
        threshold: u8,
        total_shares: u8,
    ) -> Result<Vec<Self>, RecoveryError> {
        let secret = kit.validate_and_extract_secret()?;
        let shares = ciphervault_crypto::split_secret(secret.as_bytes(), threshold, total_shares)?;

        let mut results = Vec::with_capacity(shares.len());
        for share in shares {
            let mut hasher = Hasher::new();
            hasher.update(&share.data);
            let checksum = hasher.finalize();

            results.push(Self {
                version: 1,
                vault_id_hex: kit.vault_id_hex.clone(),
                guardian_index: share.index,
                threshold,
                total_shares,
                share_data_hex: share.to_hex(),
                checksum,
                recovery_signing_pk_hex: kit.recovery_signing_pk_hex.clone(),
                recovery_encryption_pk_hex: kit.recovery_encryption_pk_hex.clone(),
                recovery_locator_hex: kit.recovery_locator_hex.clone(),
                operator_endpoints: kit.operator_endpoints.clone(),
                created_at_utc: kit.created_at_utc,
            });
        }

        Ok(results)
    }

    /// Validates the checksum and extracts the ShamirShare.
    pub fn validate_and_extract_share(
        &self,
    ) -> Result<ciphervault_crypto::ShamirShare, RecoveryError> {
        if self.version != 1
            || self.threshold < 2
            || self.total_shares < self.threshold
            || self.guardian_index == 0
            || self.guardian_index > self.total_shares
        {
            return Err(RecoveryError::InvalidKitFormat(
                "Invalid guardian threshold/index parameters".into(),
            ));
        }
        let mut raw_bytes = hex::decode(&self.share_data_hex)?;
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
        let share = ciphervault_crypto::ShamirShare::new(self.guardian_index, arr);
        arr.zeroize();
        Ok(share)
    }

    /// Combines M or more guardian threshold shares to reconstruct the complete OfflineRecoveryKit.
    pub fn combine_kits(kits: &[Self]) -> Result<OfflineRecoveryKit, RecoveryError> {
        if kits.is_empty() {
            return Err(RecoveryError::InvalidKitFormat(
                "No guardian kits provided".into(),
            ));
        }

        let threshold = kits[0].threshold;
        let total_shares = kits[0].total_shares;
        let vault_id_hex = &kits[0].vault_id_hex;

        if kits.len() < threshold as usize {
            return Err(RecoveryError::InvalidKitFormat(format!(
                "Insufficient guardian shares: received {}, requires at least {}",
                kits.len(),
                threshold
            )));
        }

        // Verify consistent parameters across all shares
        for kit in kits {
            if kit.vault_id_hex != *vault_id_hex {
                return Err(RecoveryError::InvalidKitFormat(
                    "Mismatched Vault ID across guardian shares".into(),
                ));
            }
            if kit.threshold != threshold || kit.total_shares != total_shares {
                return Err(RecoveryError::InvalidKitFormat(
                    "Mismatched threshold parameters across guardian shares".into(),
                ));
            }
            if kit.version != kits[0].version
                || kit.created_at_utc != kits[0].created_at_utc
                || kit.recovery_signing_pk_hex != kits[0].recovery_signing_pk_hex
                || kit.recovery_encryption_pk_hex != kits[0].recovery_encryption_pk_hex
                || kit.recovery_locator_hex != kits[0].recovery_locator_hex
            {
                return Err(RecoveryError::InvalidKitFormat(
                    "Mismatched recovery share set/public descriptors".into(),
                ));
            }
        }

        let mut shares = Vec::with_capacity(kits.len());
        for kit in kits {
            shares.push(kit.validate_and_extract_share()?);
        }

        let mut secret_bytes =
            ciphervault_crypto::combine_shares_with_threshold(&shares, kits[0].threshold)?;
        let secret = RecoverySecret::from_bytes(secret_bytes);
        secret_bytes.zeroize();

        let vault_id_bytes = hex::decode(vault_id_hex)?;
        if vault_id_bytes.len() != 32 {
            return Err(RecoveryError::InvalidKeyLength(vault_id_bytes.len()));
        }
        let mut vault_id = [0u8; 32];
        vault_id.copy_from_slice(&vault_id_bytes);

        let reconstructed =
            OfflineRecoveryKit::create(&vault_id, &secret, kits[0].operator_endpoints.clone())?;
        if reconstructed.recovery_signing_pk_hex != kits[0].recovery_signing_pk_hex
            || reconstructed.recovery_encryption_pk_hex != kits[0].recovery_encryption_pk_hex
            || reconstructed.recovery_locator_hex != kits[0].recovery_locator_hex
        {
            return Err(RecoveryError::InvalidKitFormat("Reconstructed secret does not match guardian public descriptors; mixed/corrupt share set".into()));
        }

        Ok(reconstructed)
    }

    /// Formats a human-readable emergency guardian sheet with warnings and verification codes.
    pub fn format_guardian_sheet(&self) -> String {
        format!(
            r#"================================================================================
          CIPHERVAULT — GUARDIAN EMERGENCY RECOVERY SHARE
================================================================================
GUARDIAN SHARE:        {} of {}
REQUIRED THRESHOLD:    Any {} of {} guardian shares required to restore vault
CRITICAL: Store this document in a physically separate, secure location.
Do NOT share this secret with unauthorized personnel.
================================================================================

Vault ID:              {}
Creation Date (UTC):   {}

GUARDIAN RECOVERY SHARE DATA:
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
            self.guardian_index,
            self.total_shares,
            self.threshold,
            self.total_shares,
            self.vault_id_hex,
            self.created_at_utc,
            self.share_data_hex,
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

    /// Parses a guardian emergency recovery sheet from formatted text.
    pub fn parse_from_printable(text: &str) -> Result<Self, RecoveryError> {
        let mut guardian_index = 0u8;
        let mut total_shares = 0u8;
        let mut threshold = 0u8;
        let mut vault_id_hex = String::new();
        let mut share_data_hex = String::new();
        let mut checksum = 0u32;
        let mut recovery_signing_pk_hex = String::new();
        let mut recovery_encryption_pk_hex = String::new();
        let mut recovery_locator_hex = String::new();
        let mut operator_endpoints = Vec::new();
        let mut created_at_utc = 0u64;

        for line in text.lines() {
            let line = line.trim();
            if let Some(stripped) = line.strip_prefix("GUARDIAN SHARE:") {
                let parts: Vec<&str> = stripped.split("of").collect();
                if parts.len() == 2 {
                    guardian_index = parts[0].trim().parse().unwrap_or(0);
                    total_shares = parts[1].trim().parse().unwrap_or(0);
                }
            } else if let Some(stripped) = line.strip_prefix("REQUIRED THRESHOLD:") {
                let words: Vec<&str> = stripped.split_whitespace().collect();
                // "Any M of N ..."
                if words.len() >= 4 && words[0].eq_ignore_ascii_case("any") {
                    threshold = words[1].parse().unwrap_or(0);
                }
            } else if let Some(stripped) = line.strip_prefix("Vault ID:") {
                vault_id_hex = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("Creation Date (UTC):") {
                created_at_utc = stripped.trim().parse().unwrap_or(0);
            } else if let Some(stripped) = line.strip_prefix("Checksum (CRC32):") {
                let hex_part = stripped.trim().trim_start_matches("0x");
                checksum = u32::from_str_radix(hex_part, 16).unwrap_or(0);
            } else if let Some(stripped) = line.strip_prefix("Recovery Signing PK:") {
                recovery_signing_pk_hex = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("Recovery Encrypt PK:") {
                recovery_encryption_pk_hex = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("Recovery Locator:") {
                recovery_locator_hex = stripped.trim().to_string();
            } else if let Some(stripped) = line.strip_prefix("- ") {
                if stripped.starts_with("http") {
                    operator_endpoints.push(stripped.trim().to_string());
                }
            } else if line.len() == 64 && hex::decode(line).is_ok() {
                share_data_hex = line.to_string();
            }
        }

        if guardian_index == 0 || threshold == 0 || total_shares == 0 || share_data_hex.is_empty() {
            return Err(RecoveryError::InvalidKitFormat(
                "Missing or invalid guardian share parameters in sheet".into(),
            ));
        }

        let kit = Self {
            version: 1,
            vault_id_hex,
            guardian_index,
            threshold,
            total_shares,
            share_data_hex,
            checksum,
            recovery_signing_pk_hex,
            recovery_encryption_pk_hex,
            recovery_locator_hex,
            operator_endpoints,
            created_at_utc,
        };

        // Validate immediately
        let _ = kit.validate_and_extract_share()?;
        Ok(kit)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, seal_box};

    #[test]
    fn guardian_mixed_share_sets_and_descriptor_tampering_are_rejected() {
        let secret = RecoverySecret::generate();
        let kit = OfflineRecoveryKit::create(&[8; 32], &secret, vec![]).unwrap();
        let first = ThresholdRecoveryKit::split_kit(&kit, 2, 3).unwrap();
        let second = ThresholdRecoveryKit::split_kit(&kit, 2, 3).unwrap();
        // Same root/descriptors but independent Shamir polynomials: reconstruction must fail.
        assert!(
            ThresholdRecoveryKit::combine_kits(&[first[0].clone(), second[1].clone()]).is_err()
        );
        let mut bad = first[1].clone();
        bad.recovery_locator_hex = "99".repeat(32);
        assert!(ThresholdRecoveryKit::combine_kits(&[first[0].clone(), bad]).is_err());
        let mut bad = first[0].clone();
        bad.guardian_index = 4;
        assert!(bad.validate_and_extract_share().is_err());
        let mut bad_kit = kit.clone();
        bad_kit.recovery_signing_pk_hex = "00".repeat(32);
        assert!(bad_kit.validate_and_extract_secret().is_err());
    }

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
    fn test_hand_copied_kit_with_wraps_and_schemeless_endpoint_parses() {
        // Simulates a hand transcription: secret wrapped over two lines
        // with dashes, scheme-less operator endpoint, human date suffix.
        let vault_id = [0x55u8; 32];
        let secret = RecoverySecret::generate();
        let kit =
            OfflineRecoveryKit::create(&vault_id, &secret, vec!["https://op1.example.com".into()])
                .unwrap();
        let secret_hex = kit.recovery_secret_hex.clone();
        let printable = kit.format_printable();
        // Rewrap the grouped secret line the way a hand copy would: two
        // lines, dash and space separators, scheme-less endpoint.
        let wrapped = format!(
            "{}-{}\n{} {}",
            &secret_hex[..16],
            &secret_hex[16..32],
            &secret_hex[32..48],
            &secret_hex[48..]
        );
        let mangled = printable
            .replace(&kit.grouped_secret_hex(), &wrapped)
            .replace("- https://op1.example.com", "- op1.example.com:8201");
        let parsed = OfflineRecoveryKit::parse_from_printable(&mangled).unwrap();
        assert_eq!(parsed.recovery_secret_hex, secret_hex);
        assert_eq!(parsed.operator_endpoints, vec!["op1.example.com:8201"]);
        // The mangled-but-complete copy still validates against its PKs.
        let extracted = parsed.validate_and_extract_secret().unwrap();
        assert_eq!(extracted.as_bytes(), secret.as_bytes());
    }

    #[test]
    fn test_threshold_recovery_split_and_combine() {
        let vault_id = [0x77u8; 32];
        let secret = RecoverySecret::generate();
        let kit = OfflineRecoveryKit::create(
            &vault_id,
            &secret,
            vec![
                "http://127.0.0.1:8787".into(),
                "http://127.0.0.1:8788".into(),
            ],
        )
        .unwrap();

        // 1. Split into 3-of-5 threshold shares
        let guardian_shares = ThresholdRecoveryKit::split_kit(&kit, 3, 5).unwrap();
        assert_eq!(guardian_shares.len(), 5);

        // 2. Test printable guardian sheet roundtrip
        let sheet = guardian_shares[0].format_guardian_sheet();
        let parsed_sheet = ThresholdRecoveryKit::parse_from_printable(&sheet).unwrap();
        assert_eq!(parsed_sheet.guardian_index, 1);
        assert_eq!(parsed_sheet.threshold, 3);
        assert_eq!(parsed_sheet.total_shares, 5);
        assert_eq!(
            parsed_sheet.share_data_hex,
            guardian_shares[0].share_data_hex
        );
        assert_eq!(parsed_sheet.checksum, guardian_shares[0].checksum);

        // 3. Combine any 3 shares (e.g. shares 1, 3, 5)
        let subset = vec![
            guardian_shares[0].clone(),
            guardian_shares[2].clone(),
            guardian_shares[4].clone(),
        ];
        let reconstructed_kit = ThresholdRecoveryKit::combine_kits(&subset).unwrap();
        assert_eq!(reconstructed_kit.vault_id_hex, kit.vault_id_hex);
        assert_eq!(
            reconstructed_kit.recovery_secret_hex,
            kit.recovery_secret_hex
        );
        assert_eq!(
            reconstructed_kit.recovery_signing_pk_hex,
            kit.recovery_signing_pk_hex
        );
        assert_eq!(
            reconstructed_kit.recovery_encryption_pk_hex,
            kit.recovery_encryption_pk_hex
        );
        assert_eq!(
            reconstructed_kit.recovery_locator_hex,
            kit.recovery_locator_hex
        );

        // 4. Insufficient shares (< threshold) fails
        let under_threshold = vec![guardian_shares[0].clone(), guardian_shares[1].clone()];
        assert!(ThresholdRecoveryKit::combine_kits(&under_threshold).is_err());
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

    #[test]
    fn test_redacted_debug_does_not_leak_secrets() {
        let vault_id = [0x55u8; 32];
        let secret = RecoverySecret::generate();
        let raw_secret_hex = hex::encode(secret.as_bytes());
        let kit = OfflineRecoveryKit::create(&vault_id, &secret, vec![]).unwrap();

        let debug_str = format!("{:?}", kit);
        assert!(!debug_str.contains(&raw_secret_hex));
        assert!(debug_str.contains("[REDACTED_SECRET]"));

        let shares = ThresholdRecoveryKit::split_kit(&kit, 2, 3).unwrap();
        let share_debug = format!("{:?}", shares[0]);
        assert!(!share_debug.contains(&shares[0].share_data_hex));
        assert!(share_debug.contains("[REDACTED_SHARE]"));
    }
}
