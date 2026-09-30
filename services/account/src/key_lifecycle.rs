//! Versioned local KEK lookup and bounded, transactional DEK rewrapping.
//! Legacy hexadecimal configuration keeps its original identifier. Versioned
//! JSON configuration retains historical keys by immutable version label.

use std::collections::BTreeMap;

use ciphervault_crypto::{
    CryptoError, DataEncryptionKey, KeyWrappingService, LocalKekService, WrappedDek,
};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct KeyRingConfig {
    active_version: String,
    keys: BTreeMap<String, String>,
}

pub(crate) struct VersionedKekService {
    active_id: String,
    keys: BTreeMap<String, LocalKekService>,
    fingerprints: BTreeMap<String, Vec<u8>>,
}

impl VersionedKekService {
    pub(crate) fn from_config(project: &str, raw: &str) -> Result<Self, ()> {
        let mut keys = BTreeMap::new();
        let mut fingerprints = BTreeMap::new();
        if !raw.trim().starts_with('{') {
            let id = format!("local:{project}");
            let key = decode_key(raw)?;
            fingerprints.insert(id.clone(), Sha256::digest(key).to_vec());
            keys.insert(id.clone(), LocalKekService::new(&id, key));
            return Ok(Self {
                active_id: id,
                keys,
                fingerprints,
            });
        }
        let config: KeyRingConfig = serde_json::from_str(raw).map_err(|_| ())?;
        if config.keys.is_empty() || config.keys.len() > 32 {
            return Err(());
        }
        for (version, raw_key) in &config.keys {
            if version.is_empty()
                || version.len() > 64
                || !version
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
            {
                return Err(());
            }
            let id = key_id(project, version);
            let key = decode_key(raw_key)?;
            fingerprints.insert(id.clone(), Sha256::digest(key).to_vec());
            keys.insert(id.clone(), LocalKekService::new(&id, key));
        }
        let active_id = key_id(project, &config.active_version);
        if !keys.contains_key(&active_id) {
            return Err(());
        }
        Ok(Self {
            active_id,
            keys,
            fingerprints,
        })
    }

    /// Version labels identify immutable key material. For a pre-fingerprint
    /// database, prove a stored DEK first so a mistyped legacy configuration
    /// cannot establish the wrong baseline or silently replace a master key.
    pub(crate) fn register(
        &self,
        db: &mut Connection,
        project: &str,
    ) -> Result<(), crate::secrets::SecretError> {
        use crate::secrets::SecretError;
        let txn = db.transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let tenant: String = txn
            .query_row(
                "SELECT tenant_id FROM projects WHERE project_id = ?1",
                [project],
                |row| row.get(0),
            )
            .optional()?
            .ok_or(SecretError::NotFound)?;
        for (id, fingerprint) in &self.fingerprints {
            let stored: Option<Option<Vec<u8>>> = txn
                .query_row(
                    "SELECT key_fingerprint FROM encryption_keys WHERE key_id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()?;
            if let Some(Some(old)) = &stored {
                if old != fingerprint {
                    return Err(SecretError::Invalid(
                        "KEK version identifies different key material".into(),
                    ));
                }
            } else {
                let blob: Option<Vec<u8>> = txn.query_row("SELECT wrapped_dek FROM secret_versions WHERE encryption_key_id = ?1 LIMIT 1",
                    [id], |row| row.get(0)).optional()?;
                if let Some(blob) = blob {
                    if blob.len() < ciphervault_crypto::NONCE_SIZE + ciphervault_crypto::TAG_SIZE {
                        return Err(SecretError::Invalid(
                            "historical DEK cannot establish KEK identity".into(),
                        ));
                    }
                    let mut nonce = [0; ciphervault_crypto::NONCE_SIZE];
                    nonce.copy_from_slice(&blob[..ciphervault_crypto::NONCE_SIZE]);
                    self.unwrap_dek(&WrappedDek {
                        kek_id: id.clone(),
                        nonce,
                        blob: blob[ciphervault_crypto::NONCE_SIZE..].to_vec(),
                    })?;
                }
                crate::secrets::ensure_kek_row(
                    &txn,
                    id,
                    &tenant,
                    project,
                    crate::state::now_utc(),
                )?;
                txn.execute(
                    "UPDATE encryption_keys SET key_fingerprint = ?1 WHERE key_id = ?2",
                    params![fingerprint, id],
                )?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    pub(crate) fn active_id(&self) -> &str {
        &self.active_id
    }

    /// Check immutable identities during an offline recovery drill without
    /// registering keys or changing the restored database.
    pub(crate) fn verify_registered_identities(&self, db: &Connection) -> Result<(), ()> {
        let has_fingerprints: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('encryption_keys') WHERE name = 'key_fingerprint')",
            [], |row| row.get(0),
        ).map_err(|_| ())?;
        // Historical databases establish key identity by authenticating every
        // retained DEK during rehearsal; do not migrate the source to add this.
        if !has_fingerprints {
            return Ok(());
        }
        for (id, fingerprint) in &self.fingerprints {
            let stored: Option<Option<Vec<u8>>> = db
                .query_row(
                    "SELECT key_fingerprint FROM encryption_keys WHERE key_id = ?1",
                    [id],
                    |row| row.get(0),
                )
                .optional()
                .map_err(|_| ())?;
            if stored
                .flatten()
                .is_some_and(|stored| stored != *fingerprint)
            {
                return Err(());
            }
        }
        Ok(())
    }
}

fn key_id(project: &str, version: &str) -> String {
    if version == "legacy" {
        format!("local:{project}")
    } else {
        format!("local:{project}:{version}")
    }
}

fn decode_key(raw: &str) -> Result<[u8; 32], ()> {
    hex::decode(raw.trim())
        .map_err(|_| ())?
        .try_into()
        .map_err(|_| ())
}

impl KeyWrappingService for VersionedKekService {
    fn wrap_dek(&self, dek: &DataEncryptionKey) -> Result<WrappedDek, CryptoError> {
        self.keys
            .get(&self.active_id)
            .ok_or(CryptoError::AuthTagVerificationFailed)?
            .wrap_dek(dek)
    }
    fn unwrap_dek(&self, wrapped: &WrappedDek) -> Result<DataEncryptionKey, CryptoError> {
        self.keys
            .get(&wrapped.kek_id)
            .ok_or(CryptoError::AuthTagVerificationFailed)?
            .unwrap_dek(wrapped)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versioned_lookup_preserves_legacy_and_fails_for_missing_or_wrong_keys() {
        let legacy = VersionedKekService::from_config("project", &"11".repeat(32)).unwrap();
        let dek = DataEncryptionKey::generate();
        let old = legacy.wrap_dek(&dek).unwrap();
        let config = serde_json::json!({"active_version":"v2", "keys":{"legacy":"11".repeat(32), "v2":"22".repeat(32)}});
        let versioned = VersionedKekService::from_config("project", &config.to_string()).unwrap();
        assert_eq!(
            versioned.unwrap_dek(&old).unwrap().as_bytes(),
            dek.as_bytes()
        );
        let new = versioned.wrap_dek(&dek).unwrap();
        assert_eq!(new.kek_id, "local:project:v2");
        assert_eq!(
            versioned.unwrap_dek(&new).unwrap().as_bytes(),
            dek.as_bytes()
        );
        assert!(legacy.unwrap_dek(&new).is_err());
        let wrong = VersionedKekService::from_config("project", &"33".repeat(32)).unwrap();
        assert!(wrong.unwrap_dek(&old).is_err());
        assert!(
            VersionedKekService::from_config("other", &config.to_string())
                .unwrap()
                .unwrap_dek(&old)
                .is_err()
        );
    }
    #[test]
    fn configuration_shape_fails_closed() {
        for raw in [
            "",
            "not-hex",
            r#"{"active_version":"missing","keys":{"v1":"aa"}}"#,
            r#"{"active_version":"v1","keys":{},"extra":true}"#,
        ] {
            assert!(VersionedKekService::from_config("p", raw).is_err());
        }
    }
}
