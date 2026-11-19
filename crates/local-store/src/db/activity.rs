//! Activity log, lease receipts, and the tamper-evident agent-audit chain.

use super::*;

impl LocalVaultStore {
    /// Records an event in the persistent local activity log.
    pub fn record_activity(
        &self,
        event_type: &str,
        summary: &str,
        details_json: &str,
    ) -> Result<(), LocalStoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT INTO activity_log (event_type, summary, details_json, created_at_utc) VALUES (?1, ?2, ?3, ?4)",
            params![event_type, summary, details_json, now],
        )?;
        Ok(())
    }

    /// Records an operator lease receipt. Renewals upsert on the lease id.
    #[allow(clippy::too_many_arguments)]
    pub fn record_lease_receipt(
        &self,
        lease_id: &str,
        operator_endpoint: &str,
        closure_digest_hex: &str,
        term_days: u32,
        bytes: u64,
        issued_at_utc: u64,
        expires_at_utc: u64,
        signature_hex: &str,
    ) -> Result<(), LocalStoreError> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        self.conn.execute(
            "INSERT OR REPLACE INTO lease_receipts (lease_id, operator_endpoint, closure_digest_hex, term_days, bytes, issued_at_utc, expires_at_utc, signature_hex, recorded_at_utc) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                lease_id,
                operator_endpoint,
                closure_digest_hex,
                term_days as i64,
                bytes as i64,
                issued_at_utc as i64,
                expires_at_utc as i64,
                signature_hex,
                now,
            ],
        )?;
        Ok(())
    }

    /// Lists lease receipts soonest-expiring first.
    pub fn list_lease_receipts(&self) -> Result<Vec<LeaseReceiptRecord>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT lease_id, operator_endpoint, closure_digest_hex, term_days, bytes, issued_at_utc, expires_at_utc, signature_hex, recorded_at_utc FROM lease_receipts ORDER BY expires_at_utc ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(LeaseReceiptRecord {
                lease_id: row.get(0)?,
                operator_endpoint: row.get(1)?,
                closure_digest_hex: row.get(2)?,
                term_days: row.get::<_, i64>(3)? as u32,
                bytes: row.get::<_, i64>(4)? as u64,
                issued_at_utc: row.get::<_, i64>(5)? as u64,
                expires_at_utc: row.get::<_, i64>(6)? as u64,
                signature_hex: row.get(7)?,
                recorded_at_utc: row.get(8)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Lists recent activity events in reverse chronological order.
    pub fn list_activity(&self, limit: usize) -> Result<Vec<ActivityEntry>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, summary, details_json, created_at_utc FROM activity_log ORDER BY created_at_utc DESC, id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(ActivityEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                summary: row.get(2)?,
                details_json: row.get(3)?,
                created_at_utc: row.get(4)?,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    const AGENT_AUDIT_SIG_DOMAIN: &[u8] = b"CipherVault-AgentAudit-v1";

    fn sanitize_audit_field(value: &str) -> String {
        value.replace(['\n', '\r'], " ")
    }

    pub(crate) fn canonical_audit_preimage(
        prev_hash: &str,
        created_at_utc: i64,
        tool: &str,
        decision: &str,
        path: &str,
        detail_json: &str,
    ) -> String {
        format!(
            "{}\n{}\n{}\n{}\n{}\n{}",
            prev_hash,
            created_at_utc,
            Self::sanitize_audit_field(tool),
            Self::sanitize_audit_field(decision),
            Self::sanitize_audit_field(path),
            Self::sanitize_audit_field(detail_json),
        )
    }

    /// Appends one entry to the tamper-evident agent-access audit
    /// chain. The entry hash covers the previous head, so rewriting or
    /// deleting history breaks verification; each entry is also signed
    /// with the device key. Only paths/decisions/counts are recorded —
    /// never secret contents.
    pub fn append_agent_audit(
        &self,
        tool: &str,
        decision: &str,
        path: &str,
        detail_json: &str,
    ) -> Result<AgentAuditEntry, LocalStoreError> {
        use sha2::Digest;
        // Single transaction: reading the previous head and inserting
        // must be atomic, or two concurrent appenders fork the chain.
        let tx = self.conn.unchecked_transaction()?;
        let prev_hash: String = tx
            .query_row(
                "SELECT entry_hash FROM agent_audit ORDER BY id DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .unwrap_or_else(|_| "GENESIS".to_string());
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let canonical =
            Self::canonical_audit_preimage(&prev_hash, now, tool, decision, path, detail_json);
        let entry_hash = hex::encode(sha2::Sha256::digest(canonical.as_bytes()));
        let (_, device_sk, _, _) = self.get_device_state()?;
        let signature = hex::encode(ciphervault_crypto::sign_with_domain(
            &device_sk,
            Self::AGENT_AUDIT_SIG_DOMAIN,
            entry_hash.as_bytes(),
        ));
        tx.execute(
            "INSERT INTO agent_audit (created_at_utc, tool, decision, path, detail_json, prev_hash, entry_hash, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![now, tool, decision, path, detail_json, prev_hash, entry_hash, signature],
        )?;
        let id = tx.last_insert_rowid();
        tx.commit()?;
        Ok(AgentAuditEntry {
            id,
            created_at_utc: now,
            tool: tool.to_string(),
            decision: decision.to_string(),
            path: path.to_string(),
            detail_json: detail_json.to_string(),
            prev_hash,
            entry_hash,
            signature,
        })
    }

    /// Lists agent-audit entries, newest first.
    pub fn list_agent_audit(&self, limit: usize) -> Result<Vec<AgentAuditEntry>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at_utc, tool, decision, path, detail_json, prev_hash, entry_hash, signature FROM agent_audit ORDER BY id DESC LIMIT ?1",
        )?;
        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AgentAuditEntry {
                id: row.get(0)?,
                created_at_utc: row.get(1)?,
                tool: row.get(2)?,
                decision: row.get(3)?,
                path: row.get(4)?,
                detail_json: row.get(5)?,
                prev_hash: row.get(6)?,
                entry_hash: row.get(7)?,
                signature: row.get(8)?,
            })
        })?;
        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Finds the newest audit entry whose detail records the given
    /// scrubbed-output SHA-256 as its `output_sha256` field, or as its
    /// `content_sha256` field (the hash of the text a person sees, such
    /// as a terminal result's `output`, inside the tool-result envelope).
    /// Exact field equality, never substring matching, so a forged or
    /// unrelated row containing the digest proves nothing.
    pub fn find_agent_audit_by_output_hash(
        &self,
        output_sha256: &str,
    ) -> Result<Option<AgentAuditEntry>, LocalStoreError> {
        let entries = self.list_agent_audit(usize::MAX)?;
        Ok(entries.into_iter().find(|e| {
            serde_json::from_str::<serde_json::Value>(&e.detail_json)
                .ok()
                .map(|v| {
                    ["output_sha256", "content_sha256"]
                        .iter()
                        .any(|field| v.get(field).and_then(|h| h.as_str()) == Some(output_sha256))
                })
                .unwrap_or(false)
        }))
    }

    /// Entry hash at a 1-based position in chain order (position 1 is
    /// the genesis entry), or None when the chain is shorter. Used to
    /// check that a fleet-anchored head is an ancestor of the local
    /// chain rather than merely equal in count.
    pub fn agent_audit_entry_hash_at(
        &self,
        position: usize,
    ) -> Result<Option<String>, LocalStoreError> {
        if position == 0 {
            return Ok(None);
        }
        let hash = self
            .conn
            .query_row(
                "SELECT entry_hash FROM agent_audit ORDER BY id ASC LIMIT 1 OFFSET ?1",
                params![(position - 1) as i64],
                |row| row.get::<_, String>(0),
            )
            .optional()?;
        Ok(hash)
    }

    /// Walks the chain from genesis recomputing every hash and
    /// signature. `first_bad_id` is the earliest entry that fails.
    pub fn verify_agent_audit(&self) -> Result<AgentAuditReport, LocalStoreError> {
        use sha2::Digest;
        let (_, device_sk, _, _) = self.get_device_state()?;
        let vk = device_sk.verifying_key();
        let vk_bytes = vk.as_bytes();
        let mut stmt = self.conn.prepare(
            "SELECT id, created_at_utc, tool, decision, path, detail_json, prev_hash, entry_hash, signature FROM agent_audit ORDER BY id ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            Ok(AgentAuditEntry {
                id: row.get(0)?,
                created_at_utc: row.get(1)?,
                tool: row.get(2)?,
                decision: row.get(3)?,
                path: row.get(4)?,
                detail_json: row.get(5)?,
                prev_hash: row.get(6)?,
                entry_hash: row.get(7)?,
                signature: row.get(8)?,
            })
        })?;
        let mut prev = "GENESIS".to_string();
        let mut count = 0usize;
        for r in rows {
            let e = r?;
            count += 1;
            let canonical = Self::canonical_audit_preimage(
                &e.prev_hash,
                e.created_at_utc,
                &e.tool,
                &e.decision,
                &e.path,
                &e.detail_json,
            );
            let expect = hex::encode(sha2::Sha256::digest(canonical.as_bytes()));
            let sig_ok = hex::decode(&e.signature)
                .ok()
                .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
                .map(|sig_bytes| {
                    if ciphervault_crypto::verify_with_domain(
                        vk_bytes,
                        Self::AGENT_AUDIT_SIG_DOMAIN,
                        e.entry_hash.as_bytes(),
                        &sig_bytes,
                    )
                    .is_ok()
                    {
                        true
                    } else if !vk.is_weak() {
                        // Legacy backwards-compatibility fallback for pre-domain entries.
                        let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
                        vk.verify_strict(e.entry_hash.as_bytes(), &sig).is_ok()
                    } else {
                        false
                    }
                })
                .unwrap_or(false);
            if e.prev_hash != prev || expect != e.entry_hash || !sig_ok {
                return Ok(AgentAuditReport {
                    ok: false,
                    entries: count,
                    head_hash: prev,
                    first_bad_id: Some(e.id),
                });
            }
            prev = e.entry_hash.clone();
        }
        Ok(AgentAuditReport {
            ok: true,
            entries: count,
            head_hash: prev,
            first_bad_id: None,
        })
    }

    /// Latest successful replication record (manual push or watcher sync),
    /// or `None` when no snapshot has ever been confirmed on operators.
    pub fn latest_sync_success(&self) -> Result<Option<ActivityEntry>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, summary, details_json, created_at_utc FROM activity_log WHERE event_type IN ('PUSH_OK','WATCH_SYNC_OK') ORDER BY created_at_utc DESC, id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |row| {
            Ok(ActivityEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                summary: row.get(2)?,
                details_json: row.get(3)?,
                created_at_utc: row.get(4)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }

    /// Latest passphrase-sealed key backup record, or `None` when no
    /// `key-backup` has ever confirmed on operators from this store.
    pub fn latest_key_backup(&self) -> Result<Option<ActivityEntry>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT id, event_type, summary, details_json, created_at_utc FROM activity_log WHERE event_type = 'KEYBACKUP_OK' ORDER BY created_at_utc DESC, id DESC LIMIT 1",
        )?;
        let mut rows = stmt.query_map([], |row| {
            Ok(ActivityEntry {
                id: row.get(0)?,
                event_type: row.get(1)?,
                summary: row.get(2)?,
                details_json: row.get(3)?,
                created_at_utc: row.get(4)?,
            })
        })?;
        Ok(rows.next().transpose()?)
    }
}
