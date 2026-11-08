//! OperatorState: Identity enrollment and device binding.

use super::*;

impl OperatorState {
    fn identity_store_path(&self) -> PathBuf {
        self.data_dir.join("identities.json")
    }

    /// Returns the I/O stripe serializing one filesystem key (CID, lease ID,
    /// or recovery locator). FNV-1a keeps this dependency-free; only the
    /// same-key-same-stripe property matters, not cross-process stability.
    pub(crate) fn io_stripe(&self, key: &str) -> &Mutex<()> {
        let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in key.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0100_0000_01b3);
        }
        &self.io_stripes[(hash as usize) % self.io_stripes.len()]
    }

    pub(crate) fn load_enrolled_identities(&self) {
        let Ok(bytes) = fs::read(self.identity_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<EnrolledIdentity>>(&bytes) else {
            return;
        };
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        identities.extend(
            records
                .into_iter()
                .map(|mut record| {
                    // Historical all-bits defaults granted storage access, not fleet control.
                    if record.permissions == u32::MAX {
                        record.permissions = PERMISSION_VAULT_DEFAULT;
                    }
                    record
                })
                .filter(|record| {
                    hex::decode(&record.vault_id_hex).map(|b| b.len()) == Ok(32)
                        && hex::decode(&record.public_key_hex).map(|b| b.len()) == Ok(32)
                        && record.vault_id_hex == record.vault_id_hex.to_ascii_lowercase()
                        && record.public_key_hex == record.public_key_hex.to_ascii_lowercase()
                        && record.account_id.as_deref().is_none_or(valid_account_id)
                        && record.device_id_hex.as_deref().is_none_or(valid_device_id)
                        && record.account_id.is_some() == record.device_id_hex.is_some()
                }),
        );
    }

    fn persist_enrolled_identities(&self) -> Result<(), String> {
        let identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities").clone();
        let encoded = serde_json::to_vec_pretty(&identities).map_err(|e| e.to_string())?;
        self.persist_atomic_secure(&self.identity_store_path(), &encoded)
    }

    pub fn is_identity_enrolled(&self, vault_id_hex: &str, public_key_hex: &str) -> bool {
        self.is_identity_enrolled_with_binding(vault_id_hex, public_key_hex, None, None)
    }

    pub fn is_identity_enrolled_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> bool {
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        let Ok((account_id, device_id_hex)) = normalize_identity_binding(account_id, device_id_hex)
        else {
            return false;
        };
        lock_or_recover(&self.enrolled_identities, "enrolled_identities")
            .iter()
            .any(|identity| {
                identity.revoked_at_utc.is_none()
                    && identity.vault_id_hex == vault_id_hex
                    && identity.public_key_hex == public_key_hex
                    && identity
                        .account_id
                        .as_deref()
                        .is_none_or(|bound| account_id.as_deref() == Some(bound))
                    && identity
                        .device_id_hex
                        .as_deref()
                        .is_none_or(|bound| device_id_hex.as_deref() == Some(bound))
            })
    }

    pub fn enroll_identity(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        permissions: u32,
    ) -> Result<(), String> {
        self.enroll_identity_with_binding(vault_id_hex, public_key_hex, permissions, None, None)
    }

    pub fn enroll_identity_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        permissions: u32,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> Result<(), String> {
        let permissions = if permissions == u32::MAX {
            PERMISSION_VAULT_DEFAULT
        } else {
            permissions
        };
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        if hex::decode(&vault_id_hex).map(|b| b.len()) != Ok(32) {
            return Err("vault_id_hex must be 32-byte hex".into());
        }
        if hex::decode(&public_key_hex).map(|b| b.len()) != Ok(32) {
            return Err("public_key_hex must be 32-byte hex".into());
        }
        let (account_id, device_id_hex) = normalize_identity_binding(account_id, device_id_hex)?;
        let _identity_guard = lock_or_recover(&self.identity_lock, "identity_lock");
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        if let Some(existing) = identities.iter_mut().find(|identity| {
            identity.vault_id_hex == vault_id_hex && identity.public_key_hex == public_key_hex
        }) {
            existing.permissions = permissions;
            existing.revoked_at_utc = None;
            // An omitted binding preserves an existing enrollment binding so
            // legacy administrative updates cannot accidentally unbind a device.
            if account_id.is_some() {
                existing.account_id = account_id.clone();
                existing.device_id_hex = device_id_hex.clone();
            }
        } else {
            identities.push(EnrolledIdentity {
                vault_id_hex: vault_id_hex.clone(),
                public_key_hex: public_key_hex.clone(),
                permissions,
                enrolled_at_utc: Utc::now().timestamp().max(0) as u64,
                revoked_at_utc: None,
                account_id: account_id.clone(),
                device_id_hex: device_id_hex.clone(),
            });
        }
        drop(identities);
        self.persist_enrolled_identities()?;
        self.audit_event(
            "identity_enrolled",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "permissions": permissions,
                "account_id": account_id,
                "device_id_hex": device_id_hex,
            }),
        );
        Ok(())
    }

    pub fn revoke_identity(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
    ) -> Result<bool, String> {
        let vault_id_hex = vault_id_hex.trim().to_ascii_lowercase();
        let public_key_hex = public_key_hex.trim().to_ascii_lowercase();
        let now = Utc::now().timestamp().max(0) as u64;
        let _identity_guard = lock_or_recover(&self.identity_lock, "identity_lock");
        let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        // Indices (not timestamps) identify what this call revoked: the
        // identity lock serializes enrollment against revocation, so no
        // push can shift the Vec between mark and rollback below.
        let mut revoked_indices = Vec::new();
        for (index, identity) in identities.iter_mut().enumerate().filter(|(_, identity)| {
            identity.vault_id_hex == vault_id_hex && identity.public_key_hex == public_key_hex
        }) {
            if identity.revoked_at_utc.is_none() {
                identity.revoked_at_utc = Some(now);
                revoked_indices.push(index);
            }
        }
        drop(identities);
        if revoked_indices.is_empty() {
            return Ok(false);
        }
        if let Err(error) = self.persist_enrolled_identities() {
            let mut identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
            for index in revoked_indices {
                if let Some(identity) = identities.get_mut(index) {
                    identity.revoked_at_utc = None;
                }
            }
            return Err(format!("Unable to persist identity revocation: {error}"));
        }
        let revoked_tokens: Vec<String> = lock_or_recover(&self.session_keys, "session_keys")
            .iter()
            .filter(|(_, key)| hex::encode(key) == public_key_hex)
            .map(|(token, _)| token.clone())
            .collect();
        if !revoked_tokens.is_empty() {
            let mut sessions = lock_or_recover(&self.sessions, "sessions");
            let mut keys = lock_or_recover(&self.session_keys, "session_keys");
            let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
            let mut removed = Vec::with_capacity(revoked_tokens.len());
            for token in &revoked_tokens {
                removed.push((
                    token.clone(),
                    sessions.remove(token),
                    keys.remove(token),
                    vaults.remove(token),
                ));
            }
            drop(vaults);
            drop(keys);
            drop(sessions);
            if let Err(error) = self.persist_sessions() {
                // Disk still holds the sessions, so memory must too.
                let mut sessions = lock_or_recover(&self.sessions, "sessions");
                let mut keys = lock_or_recover(&self.session_keys, "session_keys");
                let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
                for (token, expires_at, key, vault) in removed {
                    if let Some(expires_at) = expires_at {
                        sessions.insert(token.clone(), expires_at);
                    }
                    if let Some(key) = key {
                        keys.insert(token.clone(), key);
                    }
                    if let Some(vault) = vault {
                        vaults.insert(token, vault);
                    }
                }
                return Err(format!("Unable to persist session revocation: {error}"));
            }
        }
        self.audit_event(
            "identity_revoked",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "sessions_revoked": revoked_tokens.len(),
            }),
        );
        Ok(true)
    }

    pub fn list_enrolled_identities(&self) -> Vec<EnrolledIdentity> {
        lock_or_recover(&self.enrolled_identities, "enrolled_identities").clone()
    }
}
