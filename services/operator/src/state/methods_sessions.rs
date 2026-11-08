//! OperatorState: Sessions, challenges, peers, and admission stores.

use super::*;

impl OperatorState {
    fn session_store_path(&self) -> PathBuf {
        self.data_dir.join("sessions.json")
    }

    fn challenge_store_path(&self) -> PathBuf {
        self.data_dir.join("challenges.json")
    }

    pub(crate) fn load_sessions(&self) {
        let Ok(bytes) = fs::read(self.session_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<PersistedSession>>(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut sessions = lock_or_recover(&self.sessions, "sessions");
        let mut keys = lock_or_recover(&self.session_keys, "session_keys");
        let mut vaults = lock_or_recover(&self.session_vaults, "session_vaults");
        let mut bindings = lock_or_recover(&self.session_bindings, "session_bindings");
        for record in records {
            if record.expires_at_utc <= now || record.token.is_empty() {
                continue;
            }
            let Ok(key_bytes) = hex::decode(&record.public_key_hex) else {
                continue;
            };
            if key_bytes.len() != 32 || hex::decode(&record.vault_id_hex).map(|b| b.len()) != Ok(32)
            {
                continue;
            }
            let mut key = [0u8; 32];
            key.copy_from_slice(&key_bytes);
            let Ok(binding) = normalize_identity_binding(
                record.account_id.as_deref(),
                record.device_id_hex.as_deref(),
            ) else {
                continue;
            };
            bindings.insert(record.token.clone(), binding);
            sessions.insert(record.token.clone(), record.expires_at_utc);
            keys.insert(record.token.clone(), key);
            vaults.insert(record.token, record.vault_id_hex);
        }
    }

    pub(crate) fn load_challenges(&self) {
        let Ok(bytes) = fs::read(self.challenge_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<PersistedChallenge>>(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut challenges = lock_or_recover(&self.challenges, "challenges");
        for record in records {
            if record.expires_at_utc <= now || record.challenge_id.is_empty() {
                continue;
            }
            if hex::decode(&record.nonce_hex).map(|b| b.len()) != Ok(32)
                || hex::decode(&record.vault_id_hex).map(|b| b.len()) != Ok(32)
                || hex::decode(&record.public_key_hex).map(|b| b.len()) != Ok(32)
            {
                continue;
            }
            challenges.insert(
                record.challenge_id,
                ChallengeRecord {
                    nonce_hex: record.nonce_hex,
                    expires_at_utc: record.expires_at_utc,
                    vault_id_hex: record.vault_id_hex,
                    public_key_hex: record.public_key_hex,
                    account_id: record.account_id,
                    device_id_hex: record.device_id_hex,
                },
            );
        }
    }

    fn peer_store_path(&self) -> PathBuf {
        self.data_dir.join("peers.json")
    }

    pub(crate) fn load_peer_routing_table(&self) {
        let Ok(bytes) = fs::read(self.peer_store_path()) else {
            return;
        };
        let Ok(records) =
            serde_json::from_slice::<HashMap<String, ciphervault_storage::PeerDescriptor>>(&bytes)
        else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut peers = lock_or_recover(&self.peer_routing_table, "peer_routing_table");
        for (operator_id, peer) in records {
            if peer.operator_id == operator_id
                && peer.verify().is_ok()
                && now.saturating_sub(peer.timestamp_utc) < 86400
            {
                peers.insert(operator_id, peer);
            }
        }
    }

    pub(crate) fn persist_peer_routing_table(
        &self,
        records: &HashMap<String, ciphervault_storage::PeerDescriptor>,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.peer_store_path(), &encoded)
    }

    fn membership_store_path(&self) -> PathBuf {
        self.data_dir.join("peer-membership.json")
    }

    pub(crate) fn load_peer_membership(&self) {
        let Ok(bytes) = fs::read(self.membership_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<HashMap<String, PeerMembership>>(&bytes) else {
            return;
        };
        let mut membership = lock_or_recover(&self.peer_membership, "peer_membership");
        for (operator_id, record) in records {
            if record.last_seen_utc >= record.joined_utc {
                membership.insert(operator_id, record);
            }
        }
    }

    pub(crate) fn persist_peer_membership(
        &self,
        records: &HashMap<String, PeerMembership>,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.membership_store_path(), &encoded)
    }

    fn spent_invites_store_path(&self) -> PathBuf {
        self.data_dir.join("join-invites.json")
    }

    pub(crate) fn load_spent_invites(&self) {
        let Ok(bytes) = fs::read(self.spent_invites_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<HashMap<String, u64>>(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut spent = lock_or_recover(&self.spent_invites, "spent_invites");
        for (nonce_hex, expires_utc) in records {
            if expires_utc > now {
                spent.insert(nonce_hex, expires_utc);
            }
        }
    }

    pub(crate) fn persist_spent_invites(
        &self,
        records: &HashMap<String, u64>,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.spent_invites_store_path(), &encoded)
    }

    fn admissions_store_path(&self) -> PathBuf {
        self.data_dir.join("join-admissions.json")
    }

    pub(crate) fn load_admissions(&self) {
        let Ok(bytes) = fs::read(self.admissions_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<Vec<AdmissionRecord>>(&bytes) else {
            return;
        };
        *lock_or_recover(&self.admissions, "admissions") = records;
    }

    pub(crate) fn persist_admissions(&self, records: &[AdmissionRecord]) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.admissions_store_path(), &encoded)
    }

    fn approval_store_path(&self) -> PathBuf {
        self.data_dir.join("approvals.json")
    }

    pub(crate) fn load_approval_challenges(&self) {
        let Ok(bytes) = fs::read(self.approval_store_path()) else {
            return;
        };
        let Ok(records) = serde_json::from_slice::<
            HashMap<
                String,
                (
                    ciphervault_recovery::ApprovalChallenge,
                    Vec<ciphervault_recovery::SignedApprovalReceipt>,
                ),
            >,
        >(&bytes) else {
            return;
        };
        let now = Utc::now().timestamp() as u64;
        let mut challenges = lock_or_recover(&self.approval_challenges, "approval_challenges");
        for (challenge_id, (challenge, receipts)) in records {
            if challenge.challenge_id != challenge_id || challenge.expires_at_utc <= now {
                continue;
            }
            let verified_receipts: Vec<_> = receipts
                .into_iter()
                .filter(|receipt| {
                    receipt.challenge_id == challenge_id && receipt.verify(&challenge).is_ok()
                })
                .collect();
            challenges.insert(challenge_id, (challenge, verified_receipts));
        }
    }

    pub(crate) fn persist_approval_challenges(
        &self,
        records: &HashMap<
            String,
            (
                ciphervault_recovery::ApprovalChallenge,
                Vec<ciphervault_recovery::SignedApprovalReceipt>,
            ),
        >,
    ) -> Result<(), String> {
        let encoded = serde_json::to_vec_pretty(records).map_err(|error| error.to_string())?;
        self.persist_atomic(&self.approval_store_path(), &encoded)
    }

    fn voucher_ledger_store_path(&self) -> PathBuf {
        self.data_dir.join("voucher-ledger.json")
    }

    pub(crate) fn load_voucher_ledger(&self) {
        let path = self.voucher_ledger_store_path();
        let Ok(bytes) = fs::read(&path) else {
            return;
        };
        let mut ledger = lock_or_recover(&self.voucher_ledger, "voucher_ledger");
        if let Err(error) = ledger.decode_into(&bytes) {
            self.voucher_ledger_failed.store(true, Ordering::SeqCst);
            eprintln!("operator voucher ledger {path:?} is corrupt ({error}); voucher writes disabled until the ledger is repaired");
        }
    }

    pub(crate) fn persist_voucher_ledger(&self, encoded: &[u8]) -> Result<(), String> {
        // Nonces and byte counts are operational state, not bearer
        // secrets: plain atomic persist like the peer/approval stores.
        self.persist_atomic(&self.voucher_ledger_store_path(), encoded)
    }

    pub(crate) fn persist_sessions(&self) -> Result<(), String> {
        let sessions = lock_or_recover(&self.sessions, "sessions");
        let keys = lock_or_recover(&self.session_keys, "session_keys");
        let vaults = lock_or_recover(&self.session_vaults, "session_vaults");
        let bindings = lock_or_recover(&self.session_bindings, "session_bindings");
        let records: Vec<PersistedSession> = sessions
            .iter()
            .filter_map(|(token, expires_at_utc)| {
                Some(PersistedSession {
                    token: token.clone(),
                    expires_at_utc: *expires_at_utc,
                    public_key_hex: hex::encode(keys.get(token)?),
                    vault_id_hex: vaults.get(token)?.clone(),
                    account_id: bindings.get(token).and_then(|b| b.0.clone()),
                    device_id_hex: bindings.get(token).and_then(|b| b.1.clone()),
                })
            })
            .collect();
        let encoded = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
        self.persist_atomic_secure(&self.session_store_path(), &encoded)
    }

    fn persist_challenges(&self) -> Result<(), String> {
        let challenges = lock_or_recover(&self.challenges, "challenges");
        let records: Vec<PersistedChallenge> = challenges
            .iter()
            .map(|(challenge_id, record)| PersistedChallenge {
                challenge_id: challenge_id.clone(),
                nonce_hex: record.nonce_hex.clone(),
                expires_at_utc: record.expires_at_utc,
                vault_id_hex: record.vault_id_hex.clone(),
                public_key_hex: record.public_key_hex.clone(),
                account_id: record.account_id.clone(),
                device_id_hex: record.device_id_hex.clone(),
            })
            .collect();
        let encoded = serde_json::to_vec(&records).map_err(|error| error.to_string())?;
        self.persist_atomic_secure(&self.challenge_store_path(), &encoded)
    }

    pub(crate) fn audit_event(&self, event: &str, fields: serde_json::Value) {
        // Leaf serialization for concurrent events.log appends. This lock is
        // taken here only and never held while acquiring another lock.
        let _event_guard = lock_or_recover(&self.event_lock, "event_lock");
        let path = self.data_dir.join("events.log");
        let payload = serde_json::json!({
            "event": event,
            "operator_id": self.operator_id,
            "timestamp_utc": Utc::now().to_rfc3339(),
            "fields": fields,
        });
        if let Ok(mut file) = OpenOptions::new().create(true).append(true).open(&path) {
            let _ = writeln!(file, "{}", payload);
            #[cfg(unix)]
            {
                let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
            }
        }
    }

    pub fn issue_challenge(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
    ) -> Result<(String, String, u64), String> {
        self.issue_challenge_with_binding(vault_id_hex, public_key_hex, None, None)
    }

    pub fn issue_challenge_with_binding(
        &self,
        vault_id_hex: &str,
        public_key_hex: &str,
        account_id: Option<&str>,
        device_id_hex: Option<&str>,
    ) -> Result<(String, String, u64), String> {
        if hex::decode(vault_id_hex).map(|b| b.len()) != Ok(32) {
            return Err("vault_id_hex must be 32-byte hex".into());
        }
        if hex::decode(public_key_hex).map(|b| b.len()) != Ok(32) {
            return Err("public_key_hex must be 32-byte hex".into());
        }
        let (account_id, device_id_hex) = normalize_identity_binding(account_id, device_id_hex)?;
        let vault_id_hex = vault_id_hex.to_ascii_lowercase();
        let public_key_hex = public_key_hex.to_ascii_lowercase();
        if self.security.require_enrollment
            && !self.is_identity_enrolled_with_binding(
                &vault_id_hex,
                &public_key_hex,
                account_id.as_deref(),
                device_id_hex.as_deref(),
            )
        {
            return Err("device identity is not enrolled for this vault".into());
        }
        let mut id_bytes = [0u8; 16];
        let mut nonce_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut id_bytes);
        rand::thread_rng().fill_bytes(&mut nonce_bytes);

        let challenge_id = hex::encode(id_bytes);
        let nonce_hex = hex::encode(nonce_bytes);
        let now = Utc::now().timestamp() as u64;
        let expires_at = now + 300; // 5 minutes

        let mut lock = lock_or_recover(&self.challenges, "challenges");
        // TTL eviction: remove expired challenges
        lock.retain(|_, record| record.expires_at_utc > now);
        // Per-key cap: one identity may hold at most 64 live challenges, so a
        // single enrolled key cannot evict the whole fleet's challenges (the
        // global oldest-eviction below stays as a backstop, not the policy).
        const MAX_ACTIVE_CHALLENGES_PER_KEY: usize = 64;
        let same_key_live = lock
            .values()
            .filter(|record| {
                record
                    .vault_id_hex
                    .eq_ignore_ascii_case(vault_id_hex.as_str())
                    && record
                        .public_key_hex
                        .eq_ignore_ascii_case(public_key_hex.as_str())
            })
            .count();
        if same_key_live >= MAX_ACTIVE_CHALLENGES_PER_KEY {
            return Err("challenge quota exceeded for this identity; retry after expiry".into());
        }
        // Quota bound: if at capacity, evict oldest
        if lock.len() >= MAX_ACTIVE_CHALLENGES {
            if let Some(oldest_key) = lock
                .iter()
                .min_by_key(|(_, record)| record.expires_at_utc)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_key);
            }
        }
        lock.insert(
            challenge_id.clone(),
            ChallengeRecord {
                nonce_hex: nonce_hex.clone(),
                expires_at_utc: expires_at,
                vault_id_hex: vault_id_hex.clone(),
                public_key_hex: public_key_hex.clone(),
                account_id: account_id.clone(),
                device_id_hex: device_id_hex.clone(),
            },
        );
        drop(lock);
        if let Err(error) = self.persist_challenges() {
            lock_or_recover(&self.challenges, "challenges").remove(&challenge_id);
            return Err(format!("Unable to persist challenges: {error}"));
        }
        self.audit_event(
            "challenge_issued",
            serde_json::json!({
                "vault_id_hex": vault_id_hex,
                "public_key_hex": public_key_hex,
                "account_id": account_id,
                "device_id_hex": device_id_hex,
            }),
        );

        Ok((challenge_id, nonce_hex, expires_at))
    }

    pub fn verify_and_create_session(
        &self,
        challenge_id: &str,
        public_key_hex: &str,
        signature_hex: &str,
    ) -> Result<Option<String>, String> {
        let now = Utc::now().timestamp() as u64;
        let challenge = {
            let mut lock = lock_or_recover(&self.challenges, "challenges");
            lock.remove(challenge_id)
        };
        let Some(challenge) = challenge else {
            return Ok(None);
        };
        if let Err(error) = self.persist_challenges() {
            return Err(format!("Unable to persist challenge removal: {error}"));
        }

        if now > challenge.expires_at_utc {
            return Ok(None);
        }
        if !challenge
            .public_key_hex
            .eq_ignore_ascii_case(public_key_hex)
        {
            return Ok(None);
        }
        if self.security.require_enrollment
            && !self.is_identity_enrolled_with_binding(
                &challenge.vault_id_hex,
                &challenge.public_key_hex,
                challenge.account_id.as_deref(),
                challenge.device_id_hex.as_deref(),
            )
        {
            return Ok(None);
        }

        let Some(pk_bytes) = hex::decode(public_key_hex).ok() else {
            return Ok(None);
        };
        if pk_bytes.len() != 32 {
            return Ok(None);
        }
        let mut pk_arr = [0u8; 32];
        pk_arr.copy_from_slice(&pk_bytes);

        let Some(sig_bytes) = hex::decode(signature_hex).ok() else {
            return Ok(None);
        };
        if sig_bytes.len() != 64 {
            return Ok(None);
        }
        let mut sig_arr = [0u8; 64];
        sig_arr.copy_from_slice(&sig_bytes);

        let Some(nonce_bytes) = hex::decode(challenge.nonce_hex).ok() else {
            return Ok(None);
        };

        // Verify signature with domain separation
        if ciphervault_crypto::signatures::verify_with_domain(
            &pk_arr,
            b"operator_challenge",
            &nonce_bytes,
            &sig_arr,
        )
        .is_err()
        {
            return Ok(None);
        }

        // Generate session token
        let mut token_bytes = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut token_bytes);
        let token = hex::encode(token_bytes);
        let token_exp = now + 3600; // 1 hour

        let mut lock = lock_or_recover(&self.sessions, "sessions");
        // TTL eviction: remove expired sessions
        lock.retain(|_, exp| *exp > now);
        lock_or_recover(&self.session_keys, "session_keys")
            .retain(|token, _| lock.contains_key(token));
        lock_or_recover(&self.session_vaults, "session_vaults")
            .retain(|token, _| lock.contains_key(token));
        lock_or_recover(&self.session_bindings, "session_bindings")
            .retain(|token, _| lock.contains_key(token));
        if lock.len() >= MAX_ACTIVE_SESSIONS {
            if let Some(oldest_token) = lock
                .iter()
                .min_by_key(|(_, exp)| *exp)
                .map(|(k, _)| k.clone())
            {
                lock.remove(&oldest_token);
                lock_or_recover(&self.session_keys, "session_keys").remove(&oldest_token);
                lock_or_recover(&self.session_vaults, "session_vaults").remove(&oldest_token);
                lock_or_recover(&self.session_bindings, "session_bindings").remove(&oldest_token);
            }
        }
        lock.insert(token.clone(), token_exp);
        drop(lock);

        let mut key_lock = lock_or_recover(&self.session_keys, "session_keys");
        key_lock.insert(token.clone(), pk_arr);

        let mut vault_lock = lock_or_recover(&self.session_vaults, "session_vaults");
        vault_lock.insert(token.clone(), challenge.vault_id_hex);
        lock_or_recover(&self.session_bindings, "session_bindings").insert(
            token.clone(),
            (challenge.account_id, challenge.device_id_hex),
        );

        drop(vault_lock);
        drop(key_lock);
        if let Err(error) = self.persist_sessions() {
            // Roll back the in-memory session: without durable state the
            // login must fail cleanly rather than mint a restart-fragile one.
            lock_or_recover(&self.sessions, "sessions").remove(&token);
            lock_or_recover(&self.session_keys, "session_keys").remove(&token);
            lock_or_recover(&self.session_vaults, "session_vaults").remove(&token);
            lock_or_recover(&self.session_bindings, "session_bindings").remove(&token);
            return Err(format!("Unable to persist session: {error}"));
        }
        self.audit_event(
            "session_created",
            serde_json::json!({
                "vault_id_hex": self.get_session_vault_id(&token),
                "public_key_hex": hex::encode(pk_arr),
                "expires_at_utc": token_exp
            }),
        );

        Ok(Some(token))
    }

    pub fn revoke_session(&self, token: &str) -> Result<bool, String> {
        let removed_expires_at = lock_or_recover(&self.sessions, "sessions").remove(token);
        let removed_key = lock_or_recover(&self.session_keys, "session_keys").remove(token);
        let removed_vault = lock_or_recover(&self.session_vaults, "session_vaults").remove(token);
        let removed_binding =
            lock_or_recover(&self.session_bindings, "session_bindings").remove(token);
        let removed = removed_expires_at.is_some();
        if removed {
            if let Err(error) = self.persist_sessions() {
                // Disk still holds the session, so memory must too.
                if let Some(expires_at) = removed_expires_at {
                    lock_or_recover(&self.sessions, "sessions")
                        .insert(token.to_string(), expires_at);
                }
                if let Some(key) = removed_key {
                    lock_or_recover(&self.session_keys, "session_keys")
                        .insert(token.to_string(), key);
                }
                if let Some(vault) = removed_vault {
                    lock_or_recover(&self.session_vaults, "session_vaults")
                        .insert(token.to_string(), vault);
                }
                if let Some(binding) = removed_binding {
                    lock_or_recover(&self.session_bindings, "session_bindings")
                        .insert(token.to_string(), binding);
                }
                return Err(format!("Unable to persist session revocation: {error}"));
            }
            self.audit_event(
                "session_revoked",
                serde_json::json!({
                    "token_hash": hex::encode(compute_digest(token.as_bytes()))
                }),
            );
        }
        Ok(removed)
    }

    pub fn get_session_public_key(&self, token: &str) -> Option<[u8; 32]> {
        let lock = lock_or_recover(&self.session_keys, "session_keys");
        lock.get(token).copied()
    }

    pub fn get_session_vault_id(&self, token: &str) -> Option<String> {
        lock_or_recover(&self.session_vaults, "session_vaults")
            .get(token)
            .cloned()
    }

    pub fn validate_session_for_vault(&self, token: &str, vault_id_hex: &str) -> bool {
        let valid = self.validate_session_for_vault_inner(token, vault_id_hex);
        if !valid {
            self.metrics.observe_auth_failure();
        }
        valid
    }

    fn validate_session_for_vault_inner(&self, token: &str, vault_id_hex: &str) -> bool {
        if !self.validate_write_session(token) {
            return false;
        }
        let Some(scope) = self.get_session_vault_id(token) else {
            return false;
        };
        if !scope.eq_ignore_ascii_case(vault_id_hex) {
            return false;
        }
        if self.security.require_enrollment {
            let Some(public_key) = self.get_session_public_key(token) else {
                return false;
            };
            let binding = lock_or_recover(&self.session_bindings, "session_bindings")
                .get(token)
                .cloned()
                .unwrap_or_default();
            return self.is_identity_enrolled_with_binding(
                &scope,
                &hex::encode(public_key),
                binding.0.as_deref(),
                binding.1.as_deref(),
            );
        }
        true
    }

    /// Revalidate the enrolled principal and current capability on every request.
    pub fn session_has_permission(&self, token: &str, vault_id_hex: &str, permission: u32) -> bool {
        if !self.validate_session_for_vault(token, vault_id_hex) {
            return false;
        }
        let Some(key) = self.get_session_public_key(token) else {
            return false;
        };
        let key_hex = hex::encode(key);
        let identities = lock_or_recover(&self.enrolled_identities, "enrolled_identities");
        if let Some(identity) = identities.iter().find(|identity| {
            identity.vault_id_hex.eq_ignore_ascii_case(vault_id_hex)
                && identity.public_key_hex == key_hex
        }) {
            return identity.revoked_at_utc.is_none()
                && identity.permissions & permission == permission;
        }
        !self.security.require_enrollment && permission != PERMISSION_FLEET_ADMIN
    }

    /// Validates a session token for read-only object operations.
    /// Allows anonymous reads for disaster recovery of end-to-end encrypted ciphertext objects,
    /// or active signed session tokens.
    pub fn validate_read_session(&self, token: &str) -> bool {
        if token == "recovery_anonymous" {
            return true;
        }
        self.validate_write_session(token)
    }

    /// Validates an authenticated, challenge-signed session token for state modifications.
    /// Strictly rejects any anonymous, bypass, or expired tokens.
    pub fn validate_write_session(&self, token: &str) -> bool {
        if token.is_empty() || token == "recovery_anonymous" {
            return false;
        }
        let lock = lock_or_recover(&self.sessions, "sessions");
        if let Some(&expires_at) = lock.get(token) {
            Utc::now().timestamp() as u64 <= expires_at
        } else {
            false
        }
    }

    pub fn validate_session(&self, token: &str) -> bool {
        self.validate_write_session(token)
    }
}
