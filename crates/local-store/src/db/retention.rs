//! Pending-upload queue and snapshot retention pruning.

use super::*;

impl LocalVaultStore {
    /// Marks a snapshot upload as completed and removes it from the pending upload queue.
    pub fn mark_upload_completed(&self, snapshot_id: &[u8; 32]) -> Result<(), LocalStoreError> {
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "DELETE FROM pending_uploads WHERE snapshot_id = ?1",
            params![snapshot_id.as_slice()],
        )?;
        tx.execute(
            "UPDATE snapshots SET state = 'Replicated' WHERE snapshot_id = ?1",
            params![snapshot_id.as_slice()],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// After `snapshot_id` has been replicated, drops the queued uploads
    /// of its ancestors: the fleet now holds a newer complete state, and
    /// replicating an older snapshot afterwards would republish a stale
    /// head. The superseded snapshots keep their rows (and their state:
    /// they were never replicated); only the upload debt is cleared, so
    /// `prune` may later remove them. Snapshots on other branches stay
    /// queued. Returns how many queued uploads were cleared.
    pub fn supersede_pending_ancestors(
        &self,
        snapshot_id: &[u8; 32],
    ) -> Result<usize, LocalStoreError> {
        use std::collections::{HashMap, HashSet};

        let records = self.list_snapshots()?;
        // Parents may name a snapshot by id or by record CID (both are
        // stored as aliases), so index every record under both keys.
        let mut by_key: HashMap<Vec<u8>, usize> = HashMap::new();
        for (index, record) in records.iter().enumerate() {
            by_key.insert(record.snapshot_id.clone(), index);
            if let Ok(cid) = record.compute_record_cid() {
                by_key.insert(cid.to_vec(), index);
            }
        }
        let Some(&head) = by_key.get(snapshot_id.as_slice()) else {
            return Ok(0);
        };
        let mut ancestors: HashSet<Vec<u8>> = HashSet::new();
        let mut seen: HashSet<usize> = HashSet::from([head]);
        let mut frontier: Vec<Vec<u8>> = records[head].parent_snapshot_ids.clone();
        while let Some(parent) = frontier.pop() {
            ancestors.insert(parent.clone());
            if let Some(&index) = by_key.get(&parent) {
                if seen.insert(index) {
                    let record = &records[index];
                    ancestors.insert(record.snapshot_id.clone());
                    if let Ok(cid) = record.compute_record_cid() {
                        ancestors.insert(cid.to_vec());
                    }
                    frontier.extend(record.parent_snapshot_ids.iter().cloned());
                }
            }
        }
        let superseded: Vec<[u8; 32]> = self
            .list_pending_uploads()?
            .into_iter()
            .filter(|p| {
                p.snapshot_id != *snapshot_id
                    && (ancestors.contains(p.snapshot_id.as_slice())
                        || ancestors.contains(p.record_cid.as_slice()))
            })
            .map(|p| p.snapshot_id)
            .collect();
        let tx = self.conn.unchecked_transaction()?;
        for id in &superseded {
            tx.execute(
                "DELETE FROM pending_uploads WHERE snapshot_id = ?1",
                params![id.as_slice()],
            )?;
        }
        tx.commit()?;
        Ok(superseded.len())
    }

    /// Deletes the given snapshots (by record CID) with fail-closed guards:
    /// the active head and any snapshot with a pending upload row are skipped.
    /// Removes snapshot rows (both aliases), recovery sets, and inactive head
    /// rows, then garbage-collects chunks unreferenced by retained recovery
    /// sets. Chunk GC is skipped entirely when any retained snapshot lacks a
    /// recovery set (its references are unknowable).
    pub fn prune_snapshots(
        &self,
        record_cids: &[[u8; 32]],
    ) -> Result<PruneOutcome, LocalStoreError> {
        use std::collections::HashSet;

        let active_head_cid: Option<[u8; 32]> = self
            .get_active_head()?
            .and_then(|head| head.snapshot_id.as_slice().try_into().ok());
        let pending: HashSet<[u8; 32]> = self
            .list_pending_uploads()?
            .into_iter()
            .map(|upload| upload.record_cid)
            .collect();

        let tx = self.conn.unchecked_transaction()?;
        let mut removed = 0usize;
        let mut skipped = 0usize;
        for cid in record_cids {
            if Some(*cid) == active_head_cid || pending.contains(cid) {
                skipped += 1;
                continue;
            }
            let record_cbor: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT record_cbor FROM snapshots WHERE snapshot_id = ?1",
                    params![cid.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(record_cbor) = record_cbor else {
                continue; // Idempotent: already gone.
            };
            let record: SnapshotRecord = from_canonical_cbor(&record_cbor)?;
            let mut deleted_rows = tx.execute(
                "DELETE FROM snapshots WHERE snapshot_id = ?1",
                params![cid.as_slice()],
            )?;
            if record.snapshot_id.as_slice() != cid.as_slice() {
                deleted_rows += tx.execute(
                    "DELETE FROM snapshots WHERE snapshot_id = ?1",
                    params![record.snapshot_id.as_slice()],
                )?;
            }
            tx.execute(
                "DELETE FROM recovery_sets WHERE head_cid = ?1",
                params![cid.as_slice()],
            )?;
            tx.execute(
                "DELETE FROM heads WHERE snapshot_id = ?1 AND is_active = 0",
                params![cid.as_slice()],
            )?;
            if deleted_rows > 0 {
                removed += 1;
            }
        }

        // Chunk GC over retained recovery sets.
        let mut retained_cids = HashSet::new();
        {
            let mut stmt = tx.prepare("SELECT DISTINCT record_cbor FROM snapshots")?;
            let rows = stmt.query_map([], |row| {
                let blob: Vec<u8> = row.get(0)?;
                let record: SnapshotRecord = from_canonical_cbor(&blob).map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                let cid = record.compute_record_cid().map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        0,
                        rusqlite::types::Type::Blob,
                        Box::new(e),
                    )
                })?;
                Ok(cid)
            })?;
            for cid in rows {
                retained_cids.insert(cid?);
            }
        }
        let mut referenced = HashSet::new();
        let mut sets_complete = true;
        for cid in &retained_cids {
            let set_cbor: Option<Vec<u8>> = tx
                .query_row(
                    "SELECT set_cbor FROM recovery_sets WHERE head_cid = ?1",
                    params![cid.as_slice()],
                    |row| row.get(0),
                )
                .optional()?;
            let Some(set_cbor) = set_cbor else {
                sets_complete = false;
                break;
            };
            let set: ciphervault_format::RecoverySet = from_canonical_cbor(&set_cbor)?;
            for chunk in &set.closure.chunk_cids {
                if let Ok(arr) = <[u8; 32]>::try_from(chunk.as_slice()) {
                    referenced.insert(arr);
                }
            }
        }
        let mut chunks_removed = 0usize;
        let mut bytes_reclaimed = 0u64;
        if sets_complete {
            let doomed: Vec<([u8; 32], i64)> = {
                let mut stmt =
                    tx.prepare("SELECT chunk_cid, length(chunk_cbor) FROM local_chunks")?;
                let rows = stmt.query_map([], |row| {
                    let blob: Vec<u8> = row.get(0)?;
                    let len: i64 = row.get(1)?;
                    let mut cid = [0u8; 32];
                    if blob.len() == 32 {
                        cid.copy_from_slice(&blob);
                    }
                    Ok((cid, len))
                })?;
                let mut out = Vec::new();
                for entry in rows {
                    let (cid, len) = entry?;
                    if !referenced.contains(&cid) {
                        out.push((cid, len));
                    }
                }
                out
            };
            for (cid, len) in doomed {
                tx.execute(
                    "DELETE FROM local_chunks WHERE chunk_cid = ?1",
                    params![cid.as_slice()],
                )?;
                chunks_removed += 1;
                bytes_reclaimed += len.max(0) as u64;
            }
        }
        tx.commit()?;
        Ok(PruneOutcome {
            snapshots_removed: removed,
            snapshots_skipped_protected: skipped,
            chunks_removed,
            chunk_bytes_reclaimed: bytes_reclaimed,
            chunk_gc_skipped: !sets_complete,
        })
    }

    /// Records an upload failure attempt for a snapshot in the pending queue.
    pub fn record_upload_failure(
        &self,
        snapshot_id: &[u8; 32],
        error: &str,
    ) -> Result<(), LocalStoreError> {
        self.conn.execute(
            r#"
            UPDATE pending_uploads
            SET attempts = attempts + 1, last_error = ?2
            WHERE snapshot_id = ?1
            "#,
            params![snapshot_id.as_slice(), error],
        )?;
        Ok(())
    }

    /// Summarizes the durable replication backlog in constant output space.
    pub fn pending_upload_summary(&self) -> Result<PendingUploadSummary, LocalStoreError> {
        Ok(self.conn.query_row(
            "SELECT COUNT(*), COALESCE(SUM(CASE WHEN attempts > 0 THEN 1 ELSE 0 END), 0), MIN(created_at_utc) FROM pending_uploads",
            [],
            |row| Ok(PendingUploadSummary {
                count: row.get(0)?,
                failed_count: row.get(1)?,
                oldest_created_at_utc: row.get(2)?,
            }),
        )?)
    }

    /// Lists all snapshots currently awaiting replication in the pending queue.
    pub fn list_pending_uploads(&self) -> Result<Vec<PendingUpload>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT snapshot_id, record_cid, attempts, last_error, created_at_utc FROM pending_uploads ORDER BY created_at_utc ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let s_id: Vec<u8> = row.get(0)?;
            let r_cid: Vec<u8> = row.get(1)?;
            let attempts: u32 = row.get(2)?;
            let last_error: Option<String> = row.get(3)?;
            let created_at_utc: i64 = row.get(4)?;

            let mut snapshot_id = [0u8; 32];
            let mut record_cid = [0u8; 32];
            if s_id.len() == 32 {
                snapshot_id.copy_from_slice(&s_id);
            }
            if r_cid.len() == 32 {
                record_cid.copy_from_slice(&r_cid);
            }

            Ok(PendingUpload {
                snapshot_id,
                record_cid,
                attempts,
                last_error,
                created_at_utc,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }
}
