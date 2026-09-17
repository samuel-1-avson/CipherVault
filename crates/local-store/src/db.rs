use ed25519_dalek::SigningKey;
use rand::RngCore;
use rusqlite::{params, Connection, OptionalExtension};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ciphervault_crypto::VaultEpochKey;
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, CheckpointEvidence, ChunkWireObject, DeviceCertificate,
    GenesisRecord, HeadRecord, SnapshotRecord,
};

use crate::error::LocalStoreError;

/// Wall-clock seconds for key-creation stamps (std-only; no chrono dep here).
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

/// SQLite lock-contention waits since process start (B7). Installed as the
/// connection busy handler in [`LocalVaultStore::open`]: each lock wait bumps
/// the counter, the handler sleeps 5 ms (SQLite does not sleep for custom
/// handlers — returning `true` without sleeping would hot-spin), and it gives
/// up after ~1000 waits to preserve the historical 5 s timeout. `synchronous`
/// deliberately stays at the default FULL: the secret-bearing vault database
/// keeps crash durability, and load gates assert this counter instead of
/// weakening persistence.
static SQLITE_BUSY_RETRIES: AtomicU64 = AtomicU64::new(0);

fn counting_busy_handler(prior_waits: i32) -> bool {
    SQLITE_BUSY_RETRIES.fetch_add(1, Ordering::Relaxed);
    if prior_waits >= 1000 {
        return false;
    }
    std::thread::sleep(std::time::Duration::from_millis(5));
    true
}

/// Total SQLite busy-handler waits since process start. Soak gates assert this
/// stays at zero under sustained push load.
pub fn sqlite_busy_retries() -> u64 {
    SQLITE_BUSY_RETRIES.load(Ordering::Relaxed)
}

pub struct LocalVaultStore {
    conn: Connection,
}

pub type RecoveryDescriptors = ([u8; 32], [u8; 32], [u8; 32]);

/// Represents a local snapshot awaiting replication across remote operators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUpload {
    pub snapshot_id: [u8; 32],
    pub record_cid: [u8; 32],
    pub attempts: u32,
    pub last_error: Option<String>,
    pub created_at_utc: i64,
}

/// Outcome of one retention prune sweep.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PruneOutcome {
    pub snapshots_removed: usize,
    pub snapshots_skipped_protected: usize,
    pub chunks_removed: usize,
    pub chunk_bytes_reclaimed: u64,
    pub chunk_gc_skipped: bool,
}

/// One epoch key's rotation metadata (`created_at_utc == 0` means unknown:
/// a pre-migration key that has never been stamped).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EpochKeyInfo {
    pub epoch: u64,
    pub created_at_utc: u64,
}

/// Represents a recorded event in the vault's persistent local activity history.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ActivityEntry {
    pub id: i64,
    pub event_type: String,
    pub summary: String,
    pub details_json: String,
    pub created_at_utc: i64,
}

impl LocalVaultStore {
    /// Opens or creates a local SQLite vault database at the specified file path.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, LocalStoreError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            "#,
        )?;
        conn.busy_handler(Some(counting_busy_handler))?;
        let store = Self { conn };
        store.init_tables()?;
        store.run_migrations()?;
        Ok(store)
    }

    fn init_tables(&self) -> Result<(), LocalStoreError> {
        self.conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS vault_metadata (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                vault_id BLOB NOT NULL,
                current_epoch INTEGER NOT NULL,
                device_id BLOB NOT NULL,
                device_counter INTEGER NOT NULL,
                authority_generation INTEGER NOT NULL,
                device_signing_key BLOB NOT NULL,
                recovery_signing_pk BLOB NOT NULL,
                recovery_encryption_pk BLOB NOT NULL,
                recovery_locator BLOB NOT NULL DEFAULT (zeroblob(32)),
                genesis_cbor BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS tracked_files (
                relative_path TEXT PRIMARY KEY,
                file_id BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS epoch_keys (
                epoch INTEGER PRIMARY KEY,
                epoch_key_bytes BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS snapshots (
                snapshot_id BLOB PRIMARY KEY,
                parent_snapshot_ids TEXT NOT NULL,
                encrypted_manifest_cid BLOB NOT NULL,
                encrypted_manifest BLOB NOT NULL,
                record_cbor BLOB NOT NULL,
                state TEXT NOT NULL,
                created_at_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS local_chunks (
                chunk_cid BLOB PRIMARY KEY,
                chunk_cbor BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS heads (
                snapshot_id BLOB PRIMARY KEY,
                head_cbor BLOB NOT NULL,
                is_active INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS checkpoint_evidence (
                commitment BLOB PRIMARY KEY,
                salt BLOB NOT NULL,
                head_record_cid BLOB NOT NULL,
                chain_id INTEGER NOT NULL,
                contract_address BLOB NOT NULL,
                tx_hash BLOB NOT NULL,
                block_number INTEGER NOT NULL,
                timestamp_utc INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_checkpoint_head ON checkpoint_evidence(head_record_cid);

            CREATE TABLE IF NOT EXISTS device_certificates (
                certificate_id BLOB PRIMARY KEY,
                cert_cbor BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS recovery_sets (
                head_cid BLOB PRIMARY KEY,
                set_cbor BLOB NOT NULL
            );

            CREATE TABLE IF NOT EXISTS pending_uploads (
                snapshot_id BLOB PRIMARY KEY,
                record_cid BLOB NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                created_at_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS activity_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                event_type TEXT NOT NULL,
                summary TEXT NOT NULL,
                details_json TEXT NOT NULL DEFAULT '{}',
                created_at_utc INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_activity_created ON activity_log(created_at_utc DESC);
            "#,
        )?;
        Ok(())
    }

    fn run_migrations(&self) -> Result<(), LocalStoreError> {
        let version: u32 = self
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap_or(0);
        if version < 2 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS pending_uploads (
                    snapshot_id BLOB PRIMARY KEY,
                    record_cid BLOB NOT NULL,
                    attempts INTEGER NOT NULL DEFAULT 0,
                    last_error TEXT,
                    created_at_utc INTEGER NOT NULL
                );
                PRAGMA user_version = 2;
                "#,
            )?;
        }
        if version < 3 {
            self.conn.execute_batch(
                r#"
                ALTER TABLE epoch_keys ADD COLUMN created_at_utc INTEGER NOT NULL DEFAULT 0;
                PRAGMA user_version = 3;
                "#,
            )?;
        }
        Ok(())
    }

    /// Initializes a newly created vault in the database.
    pub fn init_vault(
        &self,
        vault_id: &[u8; 32],
        genesis: &GenesisRecord,
        device_sk: &SigningKey,
        device_id: &[u8; 32],
        initial_epoch_key: &VaultEpochKey,
        recovery_locator: &[u8; 32],
    ) -> Result<(), LocalStoreError> {
        let genesis_cbor = to_canonical_cbor(genesis)?;
        let device_sk_bytes = device_sk.to_bytes();
        let protected_device_sk = crate::keyring::protect_secret(&device_sk_bytes)?;

        self.conn.execute(
            r#"
            INSERT INTO vault_metadata (
                id, vault_id, current_epoch, device_id, device_counter,
                authority_generation, device_signing_key, recovery_signing_pk,
                recovery_encryption_pk, recovery_locator, genesis_cbor
            ) VALUES (1, ?1, 1, ?2, 0, 1, ?3, ?4, ?5, ?6, ?7)
            "#,
            params![
                vault_id.as_slice(),
                device_id.as_slice(),
                protected_device_sk.as_slice(),
                genesis.recovery_signing_pk.as_slice(),
                genesis.recovery_encryption_pk.as_slice(),
                recovery_locator.as_slice(),
                genesis_cbor
            ],
        )?;

        self.save_epoch_key(1, initial_epoch_key)?;
        Ok(())
    }

    /// Retrieves the current vault ID.
    pub fn get_vault_id(&self) -> Result<[u8; 32], LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT vault_id FROM vault_metadata WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            if blob.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&blob);
                Ok(arr)
            } else {
                Err(LocalStoreError::CorruptedRecord(format!(
                    "Invalid vault_id length: expected 32, got {}",
                    blob.len()
                )))
            }
        } else {
            Err(LocalStoreError::VaultNotInitialized)
        }
    }

    /// Retrieves recovery public descriptors (recovery_signing_pk, recovery_encryption_pk, recovery_locator).
    pub fn get_recovery_descriptors(&self) -> Result<RecoveryDescriptors, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT recovery_signing_pk, recovery_encryption_pk, recovery_locator FROM vault_metadata WHERE id = 1"
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let sig_pk_blob: Vec<u8> = row.get(0)?;
            let enc_pk_blob: Vec<u8> = row.get(1)?;
            let loc_blob: Vec<u8> = row.get(2)?;

            let mut sig_pk = [0u8; 32];
            let mut enc_pk = [0u8; 32];
            let mut loc = [0u8; 32];

            if sig_pk_blob.len() == 32 {
                sig_pk.copy_from_slice(&sig_pk_blob);
            }
            if enc_pk_blob.len() == 32 {
                enc_pk.copy_from_slice(&enc_pk_blob);
            }
            if loc_blob.len() == 32 {
                loc.copy_from_slice(&loc_blob);
            }

            Ok((sig_pk, enc_pk, loc))
        } else {
            Err(LocalStoreError::VaultNotInitialized)
        }
    }

    /// Retrieves the vault's GenesisRecord from vault_metadata.
    pub fn get_genesis_record(&self) -> Result<GenesisRecord, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT genesis_cbor FROM vault_metadata WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            from_canonical_cbor(&blob).map_err(LocalStoreError::FormatError)
        } else {
            Err(LocalStoreError::VaultNotInitialized)
        }
    }

    /// Retrieves current device state (device_id, device_sk, counter, current_epoch).
    pub fn get_device_state(&self) -> Result<([u8; 32], SigningKey, u64, u64), LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT device_id, device_signing_key, device_counter, current_epoch FROM vault_metadata WHERE id = 1"
        )?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let dev_id_blob: Vec<u8> = row.get(0)?;
            let dev_sk_blob: Vec<u8> = row.get(1)?;
            let counter: u64 = row.get(2)?;
            let epoch: u64 = row.get(3)?;

            let mut dev_id = [0u8; 32];
            if dev_id_blob.len() == 32 {
                dev_id.copy_from_slice(&dev_id_blob);
            } else {
                return Err(LocalStoreError::CorruptedRecord(format!(
                    "Invalid device_id length: expected 32, got {}",
                    dev_id_blob.len()
                )));
            }

            let decrypted_sk = crate::keyring::unprotect_secret(&dev_sk_blob)?;
            if decrypted_sk.len() != 32 {
                return Err(LocalStoreError::KeyProtectionError(
                    "Decrypted device signing key has invalid length".into(),
                ));
            }
            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&decrypted_sk);
            let sk = SigningKey::from_bytes(&sk_bytes);

            Ok((dev_id, sk, counter, epoch))
        } else {
            Err(LocalStoreError::VaultNotInitialized)
        }
    }

    /// Increments the local device counter after a snapshot commit.
    pub fn increment_device_counter(&self) -> Result<u64, LocalStoreError> {
        self.conn.execute(
            "UPDATE vault_metadata SET device_counter = device_counter + 1 WHERE id = 1",
            [],
        )?;
        let mut stmt = self
            .conn
            .prepare("SELECT device_counter FROM vault_metadata WHERE id = 1")?;
        let counter: u64 = stmt.query_row([], |r| r.get(0))?;
        Ok(counter)
    }

    /// Stores an epoch key encrypted via the OS keyring.
    pub fn save_epoch_key(&self, epoch: u64, key: &VaultEpochKey) -> Result<(), LocalStoreError> {
        let protected_bytes = crate::keyring::protect_secret(key.as_bytes())?;
        self.conn.execute(
            r#"
            INSERT INTO epoch_keys (epoch, epoch_key_bytes, created_at_utc)
            VALUES (?1, ?2, ?3)
            ON CONFLICT(epoch) DO UPDATE SET epoch_key_bytes = excluded.epoch_key_bytes
            "#,
            params![epoch, protected_bytes.as_slice(), unix_now()],
        )?;
        Ok(())
    }

    /// Lists every epoch key's rotation metadata, oldest epoch first.
    pub fn list_epoch_keys(&self) -> Result<Vec<EpochKeyInfo>, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT epoch, created_at_utc FROM epoch_keys ORDER BY epoch ASC")?;
        let rows = stmt.query_map([], |row| {
            Ok(EpochKeyInfo {
                epoch: row.get(0)?,
                created_at_utc: row.get::<_, i64>(1)? as u64,
            })
        })?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row?);
        }
        Ok(out)
    }

    /// Mints a fresh epoch key and advances `current_epoch` atomically. Old
    /// epoch keys are retained so existing snapshots stay readable; only new
    /// snapshots use the returned epoch.
    pub fn rotate_epoch_key(&self) -> Result<(u64, VaultEpochKey), LocalStoreError> {
        let current: u64 = self.conn.query_row(
            "SELECT current_epoch FROM vault_metadata WHERE id = 1",
            [],
            |row| row.get(0),
        )?;
        let next = current.checked_add(1).ok_or_else(|| {
            LocalStoreError::CorruptedRecord("current_epoch would overflow".into())
        })?;
        let key = VaultEpochKey::generate();
        let protected = crate::keyring::protect_secret(key.as_bytes())?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute(
            "INSERT INTO epoch_keys (epoch, epoch_key_bytes, created_at_utc) VALUES (?1, ?2, ?3)",
            params![next, protected.as_slice(), unix_now()],
        )?;
        tx.execute(
            "UPDATE vault_metadata SET current_epoch = ?1 WHERE id = 1",
            params![next],
        )?;
        tx.commit()?;
        Ok((next, key))
    }

    /// Retrieves and decrypts an epoch key via the OS keyring.
    pub fn get_epoch_key(&self, epoch: u64) -> Result<VaultEpochKey, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT epoch_key_bytes FROM epoch_keys WHERE epoch = ?1")?;
        let mut rows = stmt.query(params![epoch])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            let decrypted = crate::keyring::unprotect_secret(&blob)?;
            if decrypted.len() != 32 {
                return Err(LocalStoreError::KeyProtectionError(
                    "Decrypted epoch key has invalid length".into(),
                ));
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&decrypted);
            Ok(VaultEpochKey::from_bytes(arr))
        } else {
            Err(LocalStoreError::NotFound(format!(
                "Epoch key for epoch {}",
                epoch
            )))
        }
    }

    /// Adds or ensures tracking of a relative path, assigning a confidential random file_id.
    pub fn track_file(&self, rel_path: &str) -> Result<[u8; 32], LocalStoreError> {
        let normalized = rel_path.replace('\\', "/");
        let mut stmt = self
            .conn
            .prepare("SELECT file_id FROM tracked_files WHERE relative_path = ?1")?;
        let mut rows = stmt.query(params![normalized])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&blob);
            return Ok(arr);
        }

        let mut file_id = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut file_id);

        self.conn.execute(
            "INSERT INTO tracked_files (relative_path, file_id) VALUES (?1, ?2)",
            params![normalized, file_id.as_slice()],
        )?;

        Ok(file_id)
    }

    /// Returns list of all tracked files: (relative_path, file_id).
    pub fn list_tracked_files(&self) -> Result<Vec<(PathBuf, [u8; 32])>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT relative_path, file_id FROM tracked_files ORDER BY relative_path ASC",
        )?;
        let rows = stmt.query_map([], |row| {
            let path_str: String = row.get(0)?;
            let file_id_blob: Vec<u8> = row.get(1)?;
            let mut file_id = [0u8; 32];
            file_id.copy_from_slice(&file_id_blob);
            Ok((PathBuf::from(path_str), file_id))
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Removes a tracked file path from tracking. Returns true if removed, false if it wasn't tracked.
    pub fn untrack_file(&self, rel_path: &str) -> Result<bool, LocalStoreError> {
        let normalized = rel_path.replace('\\', "/");
        let count = self.conn.execute(
            "DELETE FROM tracked_files WHERE relative_path = ?1",
            params![normalized],
        )?;
        Ok(count > 0)
    }

    /// Saves a snapshot and its chunks into the local store transactionally.
    pub fn save_snapshot(
        &self,
        record: &SnapshotRecord,
        encrypted_manifest: &[u8],
        chunks: &[ChunkWireObject],
    ) -> Result<(), LocalStoreError> {
        let record_cbor = to_canonical_cbor(record)?;
        let record_cid = record.compute_record_cid()?;
        let parents_str = record
            .parent_snapshot_ids
            .iter()
            .map(hex::encode)
            .collect::<Vec<_>>()
            .join(",");

        let tx = self.conn.unchecked_transaction()?;

        // Primary index by content-addressed record_cid
        tx.execute(
            r#"
            INSERT OR REPLACE INTO snapshots (
                snapshot_id, parent_snapshot_ids, encrypted_manifest_cid,
                encrypted_manifest, record_cbor, state, created_at_utc
            ) VALUES (?1, ?2, ?3, ?4, ?5, 'Local', ?6)
            "#,
            params![
                record_cid.as_slice(),
                parents_str,
                record.encrypted_manifest_cid.as_slice(),
                encrypted_manifest,
                record_cbor,
                record.advisory_timestamp_utc
            ],
        )?;

        // Secondary alias by logical snapshot_id
        if record.snapshot_id.as_slice() != record_cid.as_slice() {
            tx.execute(
                r#"
                INSERT OR REPLACE INTO snapshots (
                    snapshot_id, parent_snapshot_ids, encrypted_manifest_cid,
                    encrypted_manifest, record_cbor, state, created_at_utc
                ) VALUES (?1, ?2, ?3, ?4, ?5, 'Local', ?6)
                "#,
                params![
                    record.snapshot_id.as_slice(),
                    parents_str,
                    record.encrypted_manifest_cid.as_slice(),
                    encrypted_manifest,
                    record_cbor,
                    record.advisory_timestamp_utc
                ],
            )?;
        }

        for chunk in chunks {
            let cid = chunk.compute_cid()?;
            let cbor = to_canonical_cbor(chunk)?;
            tx.execute(
                "INSERT OR REPLACE INTO local_chunks (chunk_cid, chunk_cbor) VALUES (?1, ?2)",
                params![cid.as_slice(), cbor],
            )?;
        }

        // Register in pending uploads queue
        tx.execute(
            r#"
            INSERT OR REPLACE INTO pending_uploads (
                snapshot_id, record_cid, attempts, last_error, created_at_utc
            ) VALUES (?1, ?2, 0, NULL, ?3)
            "#,
            params![
                record.snapshot_id.as_slice(),
                record_cid.as_slice(),
                record.advisory_timestamp_utc
            ],
        )?;

        tx.commit()?;
        Ok(())
    }

    /// Retrieves a snapshot record by snapshot_id.
    pub fn prepare_recovery_set(
        &self,
        record: &SnapshotRecord,
    ) -> anyhow::Result<ciphervault_format::RecoverySet> {
        use anyhow::Context;
        use ciphervault_format::{
            compute_digest, EpochEnvelope, RecoveryClosure, RecoverySet, SnapshotManifest,
        };
        use x25519_dalek::PublicKey as X25519PublicKey;

        let (recovery_pk, encryption_pk_bytes, locator) = self.get_recovery_descriptors()?;
        let encryption_pk = X25519PublicKey::from(encryption_pk_bytes);

        let (device_id, device_sk, _, _) = self.get_device_state()?;
        let cert = self
            .list_device_certificates()?
            .into_iter()
            .find(|c| {
                c.vault_id == record.vault_id
                    && c.device_signing_pk == device_sk.verifying_key().to_bytes()
                    && c.authority_generation == record.authority_generation
                    && c.permissions & 1 != 0
                    && c.verify(&recovery_pk).is_ok()
            })
            .context(
                "No trusted signing certificate for snapshot; cannot publish recoverable backup",
            )?;
        let epoch_key = self.get_epoch_key(record.epoch)?;
        let (_, encrypted_manifest) = self.get_snapshot(&record.compute_record_cid()?)?;
        let key = epoch_key.derive_manifest_key(record.epoch)?;
        let aad = [
            b"CipherVault-Manifest:".as_slice(),
            &record.vault_id,
            &record.epoch.to_le_bytes(),
        ]
        .concat();
        let plaintext = ciphervault_crypto::decrypt_chunk(&key, &encrypted_manifest, &aad)?;
        let manifest: SnapshotManifest = from_canonical_cbor(&plaintext)?;
        let mut envelope = EpochEnvelope {
            version: ciphervault_format::PROTOCOL_VERSION,
            vault_id: record.vault_id.clone(),
            epoch: record.epoch,
            recipient_fingerprint: encryption_pk.as_bytes().to_vec(),
            sealed_epoch_key: ciphervault_crypto::seal_box(&encryption_pk, epoch_key.as_bytes())?,
            created_at_utc: record.advisory_timestamp_utc,
            signer_device_id: device_id.to_vec(),
            signature: Vec::new(),
        };
        envelope.sign(&device_sk)?;
        let genesis = self.get_genesis_record()?;
        let records = vec![
            to_canonical_cbor(&genesis)?,
            to_canonical_cbor(&cert)?,
            to_canonical_cbor(&envelope)?,
        ];
        let mut chunks: Vec<Vec<u8>> = manifest
            .files
            .iter()
            .filter(|f| !f.is_deleted)
            .flat_map(|f| f.chunk_cids.clone())
            .collect();
        chunks.sort();
        chunks.dedup();
        let set = RecoverySet {
            closure: RecoveryClosure {
                snapshot_id: record.snapshot_id.clone(),
                snapshot_record_cid: record.compute_record_cid()?.to_vec(),
                manifest_cid: record.encrypted_manifest_cid.clone(),
                // This inventory includes all public bootstrap objects, including certificates.
                envelope_ids: records.iter().map(|r| compute_digest(r).to_vec()).collect(),
                chunk_cids: chunks,
                total_bytes: manifest.files.iter().map(|f| f.raw_length).sum(),
            },
            locator,
            records,
        };
        self.conn.execute(
            "INSERT OR REPLACE INTO recovery_sets (head_cid, set_cbor) VALUES (?1, ?2)",
            params![
                record.compute_record_cid()?.as_slice(),
                to_canonical_cbor(&set)?
            ],
        )?;
        Ok(set)
    }

    pub fn get_recovery_set(
        &self,
        head_cid: &[u8; 32],
    ) -> anyhow::Result<ciphervault_format::RecoverySet> {
        let bytes: Vec<u8> = self.conn.query_row(
            "SELECT set_cbor FROM recovery_sets WHERE head_cid = ?1",
            params![head_cid.as_slice()],
            |row| row.get(0),
        )?;
        Ok(from_canonical_cbor(&bytes)?)
    }

    pub fn recovery_objects(
        &self,
        set: &ciphervault_format::RecoverySet,
    ) -> anyhow::Result<Vec<([u8; 32], Vec<u8>)>> {
        use anyhow::{ensure, Context};
        let head: [u8; 32] = set
            .closure
            .snapshot_record_cid
            .as_slice()
            .try_into()
            .context("Invalid snapshot CID")?;
        let (record, manifest) = self.get_snapshot(&head)?;
        let mut objects = vec![
            (head, to_canonical_cbor(&record)?),
            (ciphervault_format::compute_digest(&manifest), manifest),
        ];
        let cids: Vec<[u8; 32]> = set
            .closure
            .chunk_cids
            .iter()
            .map(|c| c.as_slice().try_into().context("Invalid chunk CID"))
            .collect::<anyhow::Result<_>>()?;
        let chunks = self.get_chunks(&cids)?;
        ensure!(
            chunks.len() == cids.len(),
            "Local recovery set is missing file chunks"
        );
        for chunk in chunks {
            objects.push((chunk.compute_cid()?, to_canonical_cbor(&chunk)?));
        }
        for r in &set.records {
            objects.push((ciphervault_format::compute_digest(r), r.clone()));
        }
        Ok(objects)
    }

    pub fn get_snapshot(
        &self,
        snapshot_id: &[u8; 32],
    ) -> Result<(SnapshotRecord, Vec<u8>), LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT record_cbor, encrypted_manifest FROM snapshots WHERE snapshot_id = ?1",
        )?;
        let mut rows = stmt.query(params![snapshot_id.as_slice()])?;
        if let Some(row) = rows.next()? {
            let record_cbor: Vec<u8> = row.get(0)?;
            let manifest: Vec<u8> = row.get(1)?;
            let record: SnapshotRecord = from_canonical_cbor(&record_cbor)?;
            Ok((record, manifest))
        } else {
            Err(LocalStoreError::NotFound(format!(
                "Snapshot {}",
                hex::encode(snapshot_id)
            )))
        }
    }

    /// Retrieves all snapshots in chronological order (canonical deduplicated by CID).
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT record_cbor FROM snapshots ORDER BY created_at_utc ASC")?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let rec: SnapshotRecord = from_canonical_cbor(&blob).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })?;
            Ok(rec)
        })?;

        let mut out = Vec::new();
        let mut seen_cids = std::collections::HashSet::new();
        for r in rows {
            let rec = r?;
            if let Ok(cid) = rec.compute_record_cid() {
                if seen_cids.insert(cid) {
                    out.push(rec);
                }
            } else {
                out.push(rec);
            }
        }
        Ok(out)
    }

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

    /// Retrieves chunks for a list of chunk CIDs.
    pub fn get_chunks(&self, cids: &[[u8; 32]]) -> Result<Vec<ChunkWireObject>, LocalStoreError> {
        let mut chunks = Vec::new();
        let mut stmt = self
            .conn
            .prepare("SELECT chunk_cbor FROM local_chunks WHERE chunk_cid = ?1")?;
        for cid in cids {
            let mut rows = stmt.query(params![cid.as_slice()])?;
            if let Some(row) = rows.next()? {
                let cbor: Vec<u8> = row.get(0)?;
                let chunk: ChunkWireObject = from_canonical_cbor(&cbor)?;
                chunks.push(chunk);
            }
        }
        Ok(chunks)
    }

    /// Lists all chunk CIDs stored in the local vault database.
    pub fn list_all_chunk_cids(&self) -> Result<Vec<[u8; 32]>, LocalStoreError> {
        let mut stmt = self.conn.prepare("SELECT chunk_cid FROM local_chunks")?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let mut cid = [0u8; 32];
            if blob.len() == 32 {
                cid.copy_from_slice(&blob);
            }
            Ok(cid)
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Stores an authorized device certificate.
    pub fn save_device_certificate(&self, cert: &DeviceCertificate) -> Result<(), LocalStoreError> {
        let cbor = to_canonical_cbor(cert)?;
        self.conn.execute(
            "INSERT OR REPLACE INTO device_certificates (certificate_id, cert_cbor) VALUES (?1, ?2)",
            params![cert.certificate_id.as_slice(), cbor],
        )?;
        Ok(())
    }

    /// Lists all saved device certificates.
    pub fn list_device_certificates(&self) -> Result<Vec<DeviceCertificate>, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT cert_cbor FROM device_certificates")?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let cert: DeviceCertificate = from_canonical_cbor(&blob).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    0,
                    rusqlite::types::Type::Blob,
                    Box::new(e),
                )
            })?;
            Ok(cert)
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Updates the active head record transactionally.
    pub fn set_head(&self, head: &HeadRecord) -> Result<(), LocalStoreError> {
        let cbor = to_canonical_cbor(head)?;
        let tx = self.conn.unchecked_transaction()?;
        tx.execute("UPDATE heads SET is_active = 0", [])?;
        tx.execute(
            "INSERT OR REPLACE INTO heads (snapshot_id, head_cbor, is_active) VALUES (?1, ?2, 1)",
            params![head.snapshot_id.as_slice(), cbor],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Gets the current active head record.
    pub fn get_active_head(&self) -> Result<Option<HeadRecord>, LocalStoreError> {
        let mut stmt = self
            .conn
            .prepare("SELECT head_cbor FROM heads WHERE is_active = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let cbor: Vec<u8> = row.get(0)?;
            let head: HeadRecord = from_canonical_cbor(&cbor)?;
            Ok(Some(head))
        } else {
            Ok(None)
        }
    }

    /// Stores verified on-chain checkpoint evidence.
    pub fn save_checkpoint_evidence(
        &self,
        evidence: &CheckpointEvidence,
    ) -> Result<(), LocalStoreError> {
        self.conn.execute(
            r#"
            INSERT OR REPLACE INTO checkpoint_evidence (
                commitment, salt, head_record_cid, chain_id,
                contract_address, tx_hash, block_number, timestamp_utc
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                evidence.commitment.as_slice(),
                evidence.salt.as_slice(),
                evidence.head_record_cid.as_slice(),
                evidence.chain_id as i64,
                evidence.contract_address.as_slice(),
                evidence.tx_hash.as_slice(),
                evidence.block_number as i64,
                evidence.timestamp_utc as i64,
            ],
        )?;
        Ok(())
    }

    /// Retrieves checkpoint evidence for a specific head record CID.
    pub fn get_checkpoint_evidence(
        &self,
        head_record_cid: &[u8; 32],
    ) -> Result<Option<CheckpointEvidence>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT commitment, salt, head_record_cid, chain_id,
                   contract_address, tx_hash, block_number, timestamp_utc
            FROM checkpoint_evidence
            WHERE head_record_cid = ?1
            ORDER BY block_number DESC LIMIT 1
            "#,
        )?;
        let mut rows = stmt.query(params![head_record_cid.as_slice()])?;
        if let Some(row) = rows.next()? {
            let commitment: Vec<u8> = row.get(0)?;
            let salt: Vec<u8> = row.get(1)?;
            let head_cid: Vec<u8> = row.get(2)?;
            let chain_id: i64 = row.get(3)?;
            let contract_addr: Vec<u8> = row.get(4)?;
            let tx_hash: Vec<u8> = row.get(5)?;
            let block_num: i64 = row.get(6)?;
            let timestamp: i64 = row.get(7)?;

            Ok(Some(CheckpointEvidence {
                version: ciphervault_format::PROTOCOL_VERSION,
                commitment,
                salt,
                head_record_cid: head_cid,
                chain_id: chain_id as u64,
                contract_address: contract_addr,
                tx_hash,
                block_number: block_num as u64,
                timestamp_utc: timestamp as u64,
            }))
        } else {
            Ok(None)
        }
    }

    /// Lists all recorded checkpoint evidence entries.
    pub fn list_checkpoint_evidence(&self) -> Result<Vec<CheckpointEvidence>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            r#"
            SELECT commitment, salt, head_record_cid, chain_id,
                   contract_address, tx_hash, block_number, timestamp_utc
            FROM checkpoint_evidence
            ORDER BY block_number DESC
            "#,
        )?;
        let rows = stmt.query_map([], |row| {
            let commitment: Vec<u8> = row.get(0)?;
            let salt: Vec<u8> = row.get(1)?;
            let head_cid: Vec<u8> = row.get(2)?;
            let chain_id: i64 = row.get(3)?;
            let contract_addr: Vec<u8> = row.get(4)?;
            let tx_hash: Vec<u8> = row.get(5)?;
            let block_num: i64 = row.get(6)?;
            let timestamp: i64 = row.get(7)?;

            Ok(CheckpointEvidence {
                version: ciphervault_format::PROTOCOL_VERSION,
                commitment,
                salt,
                head_record_cid: head_cid,
                chain_id: chain_id as u64,
                contract_address: contract_addr,
                tx_hash,
                block_number: block_num as u64,
                timestamp_utc: timestamp as u64,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

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

    /// Deletes the given snapshots (by record CID) with fail-closed guards:
    /// the active head and any snapshot with a pending upload row are skipped.
    /// Removes snapshot rows (both aliases), recovery sets, and inactive head
    /// rows, then garbage-collects chunks unreferenced by retained recovery
    /// sets. Chunk GC is skipped entirely when any retained snapshot lacks a
    /// recovery set (its references are unknowable).
    pub fn prune_snapshots(&self, record_cids: &[[u8; 32]]) -> Result<PruneOutcome, LocalStoreError> {
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
                let mut stmt = tx.prepare("SELECT chunk_cid, length(chunk_cbor) FROM local_chunks")?;
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

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, RecoverySecret};
    use ciphervault_format::PROTOCOL_VERSION;

    #[test]
    fn test_vault_init_and_tracking() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let r = RecoverySecret::generate();
        let r_sk = r.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

        let vault_id = [0xAAu8; 32];
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![0u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();

        let dev_sk = generate_signing_key();
        let dev_id = [0xBBu8; 32];
        let epoch_key = VaultEpochKey::generate();

        let locator = r.derive_recovery_locator().unwrap();

        store
            .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
            .unwrap();

        let fetched_id = store.get_vault_id().unwrap();
        assert_eq!(fetched_id, vault_id);

        let file_id = store.track_file(".env").unwrap();
        let files = store.list_tracked_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, PathBuf::from(".env"));
        assert_eq!(files[0].1, file_id);
    }

    #[test]
    fn test_encrypted_key_storage() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let r = RecoverySecret::generate();
        let r_sk = r.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
        let locator = r.derive_recovery_locator().unwrap();

        let vault_id = [0xAAu8; 32];
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![0u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();

        let dev_sk = generate_signing_key();
        let dev_id = [0xBBu8; 32];
        let epoch_key = VaultEpochKey::generate();

        store
            .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
            .unwrap();

        // Inspect raw SQLite blob from database to verify it is NOT plaintext
        let raw_device_sk: Vec<u8> = store
            .conn
            .query_row(
                "SELECT device_signing_key FROM vault_metadata WHERE id = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(raw_device_sk.as_slice(), dev_sk.to_bytes().as_slice());

        let raw_epoch_key: Vec<u8> = store
            .conn
            .query_row(
                "SELECT epoch_key_bytes FROM epoch_keys WHERE epoch = 1",
                [],
                |r| r.get(0),
            )
            .unwrap();
        assert_ne!(raw_epoch_key.as_slice(), epoch_key.as_bytes().as_slice());

        // get_device_state and get_epoch_key unprotect them seamlessly
        let (_, fetched_sk, _, _) = store.get_device_state().unwrap();
        assert_eq!(fetched_sk.to_bytes(), dev_sk.to_bytes());

        let fetched_epoch = store.get_epoch_key(1).unwrap();
        assert_eq!(fetched_epoch.as_bytes(), epoch_key.as_bytes());

        // Verify descriptors can be fetched
        let (s_pk, e_pk, loc) = store.get_recovery_descriptors().unwrap();
        assert_eq!(s_pk.as_slice(), r_sk.verifying_key().as_bytes());
        assert_eq!(e_pk.as_slice(), r_enc_pk.as_bytes());
        assert_eq!(loc, locator);
    }

    #[test]
    fn test_checkpoint_evidence_storage() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let salt = [1u8; 32];
        let head_cid = [2u8; 32];
        let contract = [3u8; 20];
        let tx_hash = [4u8; 32];

        let evidence = CheckpointEvidence::new(
            salt, head_cid, 42161, contract, tx_hash, 1234567, 1700000000,
        );
        store.save_checkpoint_evidence(&evidence).unwrap();

        let fetched = store.get_checkpoint_evidence(&head_cid).unwrap().unwrap();
        assert_eq!(fetched.commitment, evidence.commitment);
        assert_eq!(fetched.block_number, 1234567);
        assert_eq!(fetched.chain_id, 42161);
        assert!(fetched.verify_commitment());
    }

    #[test]
    fn test_transactional_snapshot_and_pending_uploads() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let snap_id = [0x77u8; 32];
        let record = SnapshotRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: snap_id.to_vec(),
            parent_snapshot_ids: Vec::new(),
            device_id: vec![0x33u8; 32],
            device_counter: 1,
            authority_generation: 1,
            epoch: 1,
            encrypted_manifest_cid: vec![0x22u8; 32],
            encrypted_manifest_len: 100,
            advisory_timestamp_utc: 1000,
            signature: Vec::new(),
        };

        let chunk = ChunkWireObject {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            file_version_id: vec![0x44u8; 32],
            chunk_index: 0,
            total_chunks: 1,
            declared_padded_length: 4,
            key_epoch: 1,
            payload: vec![1, 2, 3, 4],
        };

        store
            .save_snapshot(&record, b"encrypted_manifest_data", &[chunk])
            .unwrap();

        // Verify snapshot is listed in pending_uploads
        let pending = store.list_pending_uploads().unwrap();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].snapshot_id, snap_id);
        assert_eq!(pending[0].attempts, 0);

        // Record failure
        store
            .record_upload_failure(&snap_id, "Network timeout connecting to operator")
            .unwrap();
        let pending_after_fail = store.list_pending_uploads().unwrap();
        assert_eq!(pending_after_fail[0].attempts, 1);
        assert_eq!(
            pending_after_fail[0].last_error.as_deref(),
            Some("Network timeout connecting to operator")
        );

        // Complete upload
        store.mark_upload_completed(&snap_id).unwrap();
        let pending_after_complete = store.list_pending_uploads().unwrap();
        assert!(pending_after_complete.is_empty());
    }

    #[test]
    fn test_set_head_transactional_continuity() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let dev_sk = generate_signing_key();
        let dev_id = vec![0x33u8; 32];

        let mut head1 = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: vec![0xAAu8; 32],
            parent_snapshot_ids: Vec::new(),
            closure_digest: vec![0x11u8; 32],
            device_id: dev_id.clone(),
            device_counter: 1,
            signature: Vec::new(),
        };
        head1.sign(&dev_sk).unwrap();
        store.set_head(&head1).unwrap();

        assert_eq!(
            store.get_active_head().unwrap().unwrap().snapshot_id,
            vec![0xAAu8; 32]
        );

        let mut head2 = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: vec![0xBBu8; 32],
            parent_snapshot_ids: vec![vec![0xAAu8; 32]],
            closure_digest: vec![0x22u8; 32],
            device_id: dev_id,
            device_counter: 2,
            signature: Vec::new(),
        };
        head2.sign(&dev_sk).unwrap();
        store.set_head(&head2).unwrap();

        assert_eq!(
            store.get_active_head().unwrap().unwrap().snapshot_id,
            vec![0xBBu8; 32]
        );
    }

    #[test]
    fn prune_removes_rows_sets_and_unreferenced_chunks_only() {
        use ciphervault_format::{RecoveryClosure, RecoverySet};

        let store = LocalVaultStore::open(":memory:").unwrap();
        let record = |id: u8, ts: u64| SnapshotRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: vec![id; 32],
            parent_snapshot_ids: Vec::new(),
            device_id: vec![0x33u8; 32],
            device_counter: 1,
            authority_generation: 1,
            epoch: 1,
            encrypted_manifest_cid: vec![id; 32],
            encrypted_manifest_len: 3,
            advisory_timestamp_utc: ts,
            signature: Vec::new(),
        };
        let chunk = |payload: &[u8]| ChunkWireObject {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            file_version_id: vec![0x44u8; 32],
            chunk_index: 0,
            total_chunks: 1,
            declared_padded_length: payload.len() as u32,
            key_epoch: 1,
            payload: payload.to_vec(),
        };
        let shared = chunk(b"shared-chunk-bytes");
        let only_old = chunk(b"only-old-chunk-bytes");
        let only_new = chunk(b"only-new-chunk-bytes");
        let shared_cid = shared.compute_cid().unwrap();
        let old_only_cid = only_old.compute_cid().unwrap();
        let new_only_cid = only_new.compute_cid().unwrap();

        let old = record(1, 1000);
        let new = record(2, 2000);
        let old_cid = old.compute_record_cid().unwrap();
        let new_cid = new.compute_record_cid().unwrap();
        store
            .save_snapshot(&old, b"manifest-old", &[shared.clone(), only_old.clone()])
            .unwrap();
        store
            .save_snapshot(&new, b"manifest-new", &[shared.clone(), only_new.clone()])
            .unwrap();
        // Both replicated: the pending guard must not interfere here.
        store.mark_upload_completed(&[1u8; 32]).unwrap();
        store.mark_upload_completed(&[2u8; 32]).unwrap();
        // Crafted recovery sets: old references shared+old-only, new shared+new-only.
        for (cid, chunks) in [
            (old_cid, vec![shared_cid, old_only_cid]),
            (new_cid, vec![shared_cid, new_only_cid]),
        ] {
            let set = RecoverySet {
                closure: RecoveryClosure {
                    snapshot_id: vec![0u8; 32],
                    snapshot_record_cid: cid.to_vec(),
                    manifest_cid: vec![0u8; 32],
                    envelope_ids: Vec::new(),
                    chunk_cids: chunks.iter().map(|c| c.to_vec()).collect(),
                    total_bytes: 0,
                },
                locator: [0u8; 32],
                records: Vec::new(),
            };
            store
                .conn
                .execute(
                    "INSERT INTO recovery_sets (head_cid, set_cbor) VALUES (?1, ?2)",
                    params![cid.as_slice(), to_canonical_cbor(&set).unwrap()],
                )
                .unwrap();
        }

        // Active head is fail-closed even when explicitly listed.
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![0x11u8; 32],
            snapshot_id: new_cid.to_vec(),
            parent_snapshot_ids: Vec::new(),
            closure_digest: vec![0x11u8; 32],
            device_id: vec![0x33u8; 32],
            device_counter: 2,
            signature: Vec::new(),
        };
        head.sign(&generate_signing_key()).unwrap();
        store.set_head(&head).unwrap();

        let outcome = store.prune_snapshots(&[old_cid, new_cid]).unwrap();
        assert_eq!(outcome.snapshots_removed, 1);
        assert_eq!(outcome.snapshots_skipped_protected, 1);
        assert!(!outcome.chunk_gc_skipped);
        assert_eq!(outcome.chunks_removed, 1);

        // Old rows (both aliases) and its recovery set are gone.
        assert!(store.get_snapshot(&old_cid).is_err());
        assert!(store.get_recovery_set(&old_cid).is_err());
        // New snapshot fully intact.
        assert!(store.get_snapshot(&new_cid).is_ok());
        // Shared + new-only chunks retained; old-only chunk collected.
        let remaining = store.list_all_chunk_cids().unwrap();
        assert!(remaining.contains(&shared_cid));
        assert!(remaining.contains(&new_only_cid));
        assert!(!remaining.contains(&old_only_cid));
    }

    #[test]
    fn epoch_rotation_advances_current_and_keeps_old_keys() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let r = RecoverySecret::generate();
        let r_sk = r.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
        let vault_id = [0xAAu8; 32];
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![0u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();
        let dev_sk = generate_signing_key();
        let dev_id = [0xBBu8; 32];
        let epoch_key = VaultEpochKey::generate();
        let locator = r.derive_recovery_locator().unwrap();
        store
            .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
            .unwrap();

        let (epoch2, _) = store.rotate_epoch_key().unwrap();
        assert_eq!(epoch2, 2);
        let (_, _, _, current) = store.get_device_state().unwrap();
        assert_eq!(current, 2);
        // Old key still retrievable and distinct.
        let key1 = store.get_epoch_key(1).unwrap();
        let key2 = store.get_epoch_key(2).unwrap();
        assert_ne!(key1.as_bytes(), key2.as_bytes());
        let infos = store.list_epoch_keys().unwrap();
        assert_eq!(infos.len(), 2);
        assert!(infos.iter().all(|info| info.created_at_utc > 0));
        assert!(infos[0].created_at_utc <= infos[1].created_at_utc);
    }

    #[test]
    fn epoch_key_migration_backfills_unknown_stamps() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        // Simulate a pre-migration v2 database with one legacy row.
        store
            .conn
            .execute_batch("ALTER TABLE epoch_keys DROP COLUMN created_at_utc;")
            .unwrap();
        store
            .conn
            .execute(
                "INSERT INTO epoch_keys (epoch, epoch_key_bytes) VALUES (?1, ?2)",
                params![1u64, vec![7u8; 48]],
            )
            .unwrap();
        store.conn.execute("PRAGMA user_version = 2", []).unwrap();
        store.run_migrations().unwrap();
        let version: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 3);
        let infos = store.list_epoch_keys().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].created_at_utc, 0);
    }
}
