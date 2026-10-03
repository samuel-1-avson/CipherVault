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
use zeroize::Zeroizing;

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

/// Aggregate durable replication backlog without loading snapshot rows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingUploadSummary {
    pub count: u64,
    pub failed_count: u64,
    pub oldest_created_at_utc: Option<i64>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LeaseReceiptRecord {
    pub lease_id: String,
    pub operator_endpoint: String,
    pub closure_digest_hex: String,
    pub term_days: u32,
    pub bytes: u64,
    pub issued_at_utc: u64,
    pub expires_at_utc: u64,
    pub signature_hex: String,
    pub recorded_at_utc: i64,
}

impl LocalVaultStore {
    /// Opens or creates a local SQLite vault database at the specified file path.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, LocalStoreError> {
        let conn = Connection::open(db_path)?;
        conn.execute_batch(
            r#"
            PRAGMA journal_mode = WAL;
            PRAGMA foreign_keys = ON;
            "#,
        )?;
        conn.busy_handler(Some(counting_busy_handler))?;
        let store = Self { conn };
        store.init_tables()?;
        store.run_migrations()?;
        Ok(store)
    }

    /// Opens an existing vault database strictly read-only (no WAL, no
    /// migrations, no writes of any kind). Migration planning/apply/verify
    /// use this so legacy vaults stay byte-identical until the explicit
    /// shred step (§F-§3); any write attempt fails at the SQLite layer.
    pub fn open_read_only<P: AsRef<Path>>(db_path: P) -> Result<Self, LocalStoreError> {
        use rusqlite::OpenFlags;
        let conn = Connection::open_with_flags(
            db_path,
            OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )?;
        conn.execute_batch("PRAGMA foreign_keys = ON;")?;
        conn.busy_handler(Some(counting_busy_handler))?;
        Ok(Self { conn })
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

            CREATE TABLE IF NOT EXISTS lease_receipts (
                lease_id TEXT PRIMARY KEY,
                operator_endpoint TEXT NOT NULL,
                closure_digest_hex TEXT NOT NULL,
                term_days INTEGER NOT NULL,
                bytes INTEGER NOT NULL,
                issued_at_utc INTEGER NOT NULL,
                expires_at_utc INTEGER NOT NULL,
                signature_hex TEXT NOT NULL,
                recorded_at_utc INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_lease_expires ON lease_receipts(expires_at_utc ASC);

            CREATE TABLE IF NOT EXISTS scoped_context (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                tenant_id TEXT NOT NULL,
                workspace_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                updated_at_utc INTEGER NOT NULL
            );

            CREATE TABLE IF NOT EXISTS scoped_secret_cache (
                secret_id TEXT PRIMARY KEY,
                tenant_id TEXT NOT NULL,
                project_id TEXT NOT NULL,
                environment_id TEXT NOT NULL,
                repository_binding_id TEXT,
                service_id TEXT,
                name TEXT NOT NULL,
                secret_type TEXT NOT NULL DEFAULT 'key_value',
                current_version INTEGER NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                updated_at_utc INTEGER NOT NULL,
                UNIQUE (project_id, environment_id, name)
            );
            CREATE INDEX IF NOT EXISTS idx_scoped_secret_cache_project ON scoped_secret_cache(project_id, environment_id);

            CREATE TABLE IF NOT EXISTS scoped_binding_cache (
                binding_id TEXT PRIMARY KEY,
                project_id TEXT NOT NULL,
                provider TEXT NOT NULL,
                external_repo_id TEXT NOT NULL,
                repo_full_name TEXT NOT NULL,
                repo_url TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                updated_at_utc INTEGER NOT NULL,
                UNIQUE (project_id, provider, external_repo_id)
            );
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
        if version < 4 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS lease_receipts (
                    lease_id TEXT PRIMARY KEY,
                    operator_endpoint TEXT NOT NULL,
                    closure_digest_hex TEXT NOT NULL,
                    term_days INTEGER NOT NULL,
                    bytes INTEGER NOT NULL,
                    issued_at_utc INTEGER NOT NULL,
                    expires_at_utc INTEGER NOT NULL,
                    signature_hex TEXT NOT NULL,
                    recorded_at_utc INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_lease_expires ON lease_receipts(expires_at_utc ASC);
                PRAGMA user_version = 4;
                "#,
            )?;
        }
        if version < 5 {
            self.conn.execute_batch(
                r#"
                CREATE TABLE IF NOT EXISTS scoped_context (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    tenant_id TEXT NOT NULL,
                    workspace_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    updated_at_utc INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS scoped_secret_cache (
                    secret_id TEXT PRIMARY KEY,
                    tenant_id TEXT NOT NULL,
                    project_id TEXT NOT NULL,
                    environment_id TEXT NOT NULL,
                    repository_binding_id TEXT,
                    service_id TEXT,
                    name TEXT NOT NULL,
                    secret_type TEXT NOT NULL DEFAULT 'key_value',
                    current_version INTEGER NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    updated_at_utc INTEGER NOT NULL,
                    UNIQUE (project_id, environment_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_scoped_secret_cache_project ON scoped_secret_cache(project_id, environment_id);

                CREATE TABLE IF NOT EXISTS scoped_binding_cache (
                    binding_id TEXT PRIMARY KEY,
                    project_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    external_repo_id TEXT NOT NULL,
                    repo_full_name TEXT NOT NULL,
                    repo_url TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'active',
                    updated_at_utc INTEGER NOT NULL,
                    UNIQUE (project_id, provider, external_repo_id)
                );
                PRAGMA user_version = 5;
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
        self.init_vault_at_epoch(
            vault_id,
            genesis,
            device_sk,
            device_id,
            initial_epoch_key,
            recovery_locator,
            1,
        )
    }

    /// Initializes vault metadata at an explicit epoch. Fresh `init` uses
    /// epoch 1; post-recovery rebuilds resume at the recovered snapshot's
    /// epoch so the next push mints `epoch + 1` instead of rewinding to 2.
    /// The epoch must be nonzero — epoch 0 has no keys by construction.
    /// Eight params mirror [`LocalVaultStore::init_vault`] plus the epoch;
    /// a builder would churn every init call site for no safety gain.
    #[allow(clippy::too_many_arguments)]
    pub fn init_vault_at_epoch(
        &self,
        vault_id: &[u8; 32],
        genesis: &GenesisRecord,
        device_sk: &SigningKey,
        device_id: &[u8; 32],
        initial_epoch_key: &VaultEpochKey,
        recovery_locator: &[u8; 32],
        epoch: u64,
    ) -> Result<(), LocalStoreError> {
        if epoch == 0 {
            return Err(LocalStoreError::CorruptedRecord(
                "cannot init vault at epoch 0".into(),
            ));
        }
        let genesis_cbor = to_canonical_cbor(genesis)?;
        let device_sk_bytes = device_sk.to_bytes();
        let protected_device_sk = crate::keyring::protect_secret(&device_sk_bytes)?;

        self.conn.execute(
            r#"
            INSERT INTO vault_metadata (
                id, vault_id, current_epoch, device_id, device_counter,
                authority_generation, device_signing_key, recovery_signing_pk,
                recovery_encryption_pk, recovery_locator, genesis_cbor
            ) VALUES (1, ?1, ?2, ?3, 0, 1, ?4, ?5, ?6, ?7, ?8)
            "#,
            params![
                vault_id.as_slice(),
                epoch,
                device_id.as_slice(),
                protected_device_sk.as_slice(),
                genesis.recovery_signing_pk.as_slice(),
                genesis.recovery_encryption_pk.as_slice(),
                recovery_locator.as_slice(),
                genesis_cbor
            ],
        )?;

        self.save_epoch_key(epoch, initial_epoch_key)?;
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

            let decrypted_sk = Zeroizing::new(crate::keyring::unprotect_secret(&dev_sk_blob)?);
            if decrypted_sk.len() != 32 {
                return Err(LocalStoreError::KeyProtectionError(
                    "Decrypted device signing key has invalid length".into(),
                ));
            }
            let mut sk_bytes = Zeroizing::new([0u8; 32]);
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
            let decrypted = Zeroizing::new(crate::keyring::unprotect_secret(&blob)?);
            if decrypted.len() != 32 {
                return Err(LocalStoreError::KeyProtectionError(
                    "Decrypted epoch key has invalid length".into(),
                ));
            }
            let mut arr = Zeroizing::new([0u8; 32]);
            arr.copy_from_slice(&decrypted);
            Ok(VaultEpochKey::from_bytes(*arr))
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

    /// Validate certified signing authority before persisting a new snapshot/counter.
    pub fn validate_capture_authority(
        &self,
        device_key: &SigningKey,
        authority_generation: u64,
    ) -> anyhow::Result<DeviceCertificate> {
        self.validate_capture_authority_for_key(
            device_key.verifying_key().as_bytes(),
            authority_generation,
        )
    }

    /// Select the latest root-certified generation for a signing key.
    pub fn latest_capture_authority_for_key(
        &self,
        public_key: &[u8; 32],
    ) -> anyhow::Result<DeviceCertificate> {
        use anyhow::Context;
        let vault_id = self.get_vault_id()?;
        let (root, _, _) = self.get_recovery_descriptors()?;
        let generation = self
            .list_device_certificates()?
            .iter()
            .filter(|certificate| {
                certificate.vault_id == vault_id
                    && certificate.device_signing_pk == public_key
                    && certificate.permissions & 1 != 0
                    && certificate.verify(&root).is_ok()
            })
            .map(|certificate| certificate.authority_generation)
            .max()
            .context("No trusted capture authority for this signing key")?;
        self.validate_capture_authority_for_key(public_key, generation)
    }

    pub fn validate_capture_authority_for_key(
        &self,
        public_key: &[u8; 32],
        authority_generation: u64,
    ) -> anyhow::Result<DeviceCertificate> {
        use anyhow::Context;
        let vault = self.get_vault_id()?;
        let (recovery_root, _, _) = self.get_recovery_descriptors()?;
        self.list_device_certificates()?
            .into_iter()
            .find(|certificate| {
                certificate.version == ciphervault_format::PROTOCOL_VERSION
                    && certificate.vault_id == vault
                    && certificate.device_signing_pk == *public_key
                    && certificate.authority_generation == authority_generation
                    && certificate.permissions & 1 != 0
                    && certificate.verify(&recovery_root).is_ok()
            })
            .context("No trusted signing certificate; capture must not advance local state")
    }

    /// Build and persist the authenticated recovery inventory of a saved snapshot.
    pub fn prepare_recovery_set(
        &self,
        record: &SnapshotRecord,
    ) -> anyhow::Result<ciphervault_format::RecoverySet> {
        let (_, device_sk, _, _) = self.get_device_state()?;
        self.prepare_recovery_set_signed(record, device_sk.verifying_key().as_bytes(), |envelope| {
            envelope.sign(&device_sk)
        })
    }

    /// Build an inventory using the hardware authority that signed the snapshot.
    /// Existing inventories are immutable: retries return their exact original bytes.
    pub fn prepare_recovery_set_with_hsm(
        &self,
        record: &SnapshotRecord,
        hsm: &dyn ciphervault_crypto::HardwareSecurityModule,
        slot: ciphervault_crypto::HsmSlot,
    ) -> anyhow::Result<ciphervault_format::RecoverySet> {
        use anyhow::Context;
        let public_key: [u8; 32] = hsm
            .get_public_key(slot)?
            .as_slice()
            .try_into()
            .context("Hardware signing key must be a 32-byte Ed25519 key")?;
        self.prepare_recovery_set_signed(record, &public_key, |envelope| {
            envelope.sign_with_hsm(hsm, slot)
        })
    }

    fn prepare_recovery_set_signed(
        &self,
        record: &SnapshotRecord,
        public_key: &[u8; 32],
        sign_envelope: impl FnOnce(
            &mut ciphervault_format::EpochEnvelope,
        ) -> Result<(), ciphervault_format::FormatError>,
    ) -> anyhow::Result<ciphervault_format::RecoverySet> {
        use ciphervault_format::{
            compute_digest, EpochEnvelope, RecoveryClosure, RecoverySet, SnapshotManifest,
        };
        use x25519_dalek::PublicKey as X25519PublicKey;

        let record_cid = record.compute_record_cid()?;
        let existing: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT set_cbor FROM recovery_sets WHERE head_cid = ?1",
                params![record_cid.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(bytes) = existing {
            let set: RecoverySet = from_canonical_cbor(&bytes)?;
            anyhow::ensure!(
                set.closure.snapshot_record_cid == record_cid
                    && set.closure.snapshot_id == record.snapshot_id
                    && set.closure.manifest_cid == record.encrypted_manifest_cid,
                "Stored recovery set does not match its snapshot"
            );
            return Ok(set);
        }
        anyhow::ensure!(
            record.version == ciphervault_format::PROTOCOL_VERSION
                && record.vault_id == self.get_vault_id()?,
            "Snapshot version/vault mismatch"
        );
        record.verify(public_key)?;
        let (_, encryption_pk_bytes, locator) = self.get_recovery_descriptors()?;
        let encryption_pk = X25519PublicKey::from(encryption_pk_bytes);

        let cert =
            self.validate_capture_authority_for_key(public_key, record.authority_generation)?;
        let epoch_key = self.get_epoch_key(record.epoch)?;
        let (_, encrypted_manifest) = self.get_snapshot(&record.compute_record_cid()?)?;
        let key = Zeroizing::new(epoch_key.derive_manifest_key(record.epoch)?);
        let aad = [
            b"CipherVault-Manifest:".as_slice(),
            &record.vault_id,
            &record.epoch.to_le_bytes(),
        ]
        .concat();
        let plaintext = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
            &key,
            &encrypted_manifest,
            &aad,
        )?);
        let manifest: SnapshotManifest = from_canonical_cbor(&plaintext)?;
        anyhow::ensure!(
            manifest.version == ciphervault_format::PROTOCOL_VERSION
                && manifest.vault_id == record.vault_id
                && manifest.epoch == record.epoch
                && manifest.snapshot_id == record.snapshot_id,
            "Snapshot manifest binding mismatch"
        );
        let mut envelope = EpochEnvelope {
            version: ciphervault_format::PROTOCOL_VERSION,
            vault_id: record.vault_id.clone(),
            epoch: record.epoch,
            recipient_fingerprint: encryption_pk.as_bytes().to_vec(),
            sealed_epoch_key: ciphervault_crypto::seal_box(&encryption_pk, epoch_key.as_bytes())?,
            created_at_utc: record.advisory_timestamp_utc,
            signer_device_id: record.device_id.clone(),
            signature: Vec::new(),
        };
        sign_envelope(&mut envelope)?;
        envelope.verify(public_key)?;
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
            "INSERT OR IGNORE INTO recovery_sets (head_cid, set_cbor) VALUES (?1, ?2)",
            params![
                record.compute_record_cid()?.as_slice(),
                to_canonical_cbor(&set)?
            ],
        )?;
        // Concurrent preparers converge on the first complete durable inventory.
        self.get_recovery_set(&record_cid)
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

    /// Gets the retained signed head bound to a snapshot record CID, including
    /// inactive snapshots awaiting replication after a newer capture.
    pub fn get_head_for_snapshot(
        &self,
        record_cid: &[u8; 32],
    ) -> Result<Option<HeadRecord>, LocalStoreError> {
        let cbor: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT head_cbor FROM heads WHERE snapshot_id = ?1",
                params![record_cid.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        cbor.map(|bytes| from_canonical_cbor(&bytes).map_err(LocalStoreError::from))
            .transpose()
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

/// Active scoped context (single-row mirror of the server-side selection).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopedContext {
    pub tenant_id: String,
    pub workspace_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub updated_at_utc: i64,
}

/// Cached secret metadata row. Values are never cached locally in schema v5;
/// ciphertext caching arrives with offline bundles in Phase 7.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedSecretMeta {
    pub secret_id: String,
    pub tenant_id: String,
    pub project_id: String,
    pub environment_id: String,
    pub repository_binding_id: Option<String>,
    pub service_id: Option<String>,
    pub name: String,
    pub secret_type: String,
    pub current_version: i64,
    pub status: String,
    pub updated_at_utc: i64,
}

/// Cached repository-binding row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CachedBinding {
    pub binding_id: String,
    pub project_id: String,
    pub provider: String,
    pub external_repo_id: String,
    pub repo_full_name: String,
    pub repo_url: String,
    pub status: String,
    pub updated_at_utc: i64,
}

impl LocalVaultStore {
    /// Stores the active scoped context (single row, id = 1).
    pub fn set_scoped_context(
        &self,
        tenant_id: &str,
        workspace_id: &str,
        project_id: &str,
        environment_id: &str,
    ) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_context (id, tenant_id, workspace_id, project_id, environment_id, updated_at_utc)
             VALUES (1, ?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET tenant_id = excluded.tenant_id,
                workspace_id = excluded.workspace_id, project_id = excluded.project_id,
                environment_id = excluded.environment_id, updated_at_utc = excluded.updated_at_utc",
            params![
                tenant_id,
                workspace_id,
                project_id,
                environment_id,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Returns the active scoped context, if any.
    pub fn get_scoped_context(&self) -> Result<Option<ScopedContext>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT tenant_id, workspace_id, project_id, environment_id, updated_at_utc
                 FROM scoped_context WHERE id = 1",
                [],
                |row| {
                    Ok(ScopedContext {
                        tenant_id: row.get(0)?,
                        workspace_id: row.get(1)?,
                        project_id: row.get(2)?,
                        environment_id: row.get(3)?,
                        updated_at_utc: row.get(4)?,
                    })
                },
            )
            .optional()?)
    }

    /// Inserts or refreshes one cached secret metadata row, keyed by
    /// `(project_id, environment_id, name)`.
    pub fn upsert_cached_secret(&self, meta: &CachedSecretMeta) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_secret_cache (secret_id, tenant_id, project_id, environment_id,
                 repository_binding_id, service_id, name, secret_type, current_version, status,
                 updated_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11)
             ON CONFLICT(project_id, environment_id, name) DO UPDATE SET secret_id = excluded.secret_id,
                tenant_id = excluded.tenant_id, repository_binding_id = excluded.repository_binding_id,
                service_id = excluded.service_id, secret_type = excluded.secret_type,
                current_version = excluded.current_version, status = excluded.status,
                updated_at_utc = excluded.updated_at_utc",
            params![
                meta.secret_id,
                meta.tenant_id,
                meta.project_id,
                meta.environment_id,
                meta.repository_binding_id,
                meta.service_id,
                meta.name,
                meta.secret_type,
                meta.current_version,
                meta.status,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Looks up one cached secret by scope and name.
    pub fn get_cached_secret(
        &self,
        project_id: &str,
        environment_id: &str,
        name: &str,
    ) -> Result<Option<CachedSecretMeta>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT secret_id, tenant_id, project_id, environment_id, repository_binding_id,
                        service_id, name, secret_type, current_version, status, updated_at_utc
                 FROM scoped_secret_cache
                 WHERE project_id = ?1 AND environment_id = ?2 AND name = ?3",
                params![project_id, environment_id, name],
                |row| {
                    Ok(CachedSecretMeta {
                        secret_id: row.get(0)?,
                        tenant_id: row.get(1)?,
                        project_id: row.get(2)?,
                        environment_id: row.get(3)?,
                        repository_binding_id: row.get(4)?,
                        service_id: row.get(5)?,
                        name: row.get(6)?,
                        secret_type: row.get(7)?,
                        current_version: row.get(8)?,
                        status: row.get(9)?,
                        updated_at_utc: row.get(10)?,
                    })
                },
            )
            .optional()?)
    }

    /// Inserts or refreshes one cached repository binding.
    pub fn upsert_cached_binding(&self, binding: &CachedBinding) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT INTO scoped_binding_cache (binding_id, project_id, provider, external_repo_id,
                 repo_full_name, repo_url, status, updated_at_utc)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(project_id, provider, external_repo_id) DO UPDATE SET
                binding_id = excluded.binding_id, repo_full_name = excluded.repo_full_name,
                repo_url = excluded.repo_url, status = excluded.status,
                updated_at_utc = excluded.updated_at_utc",
            params![
                binding.binding_id,
                binding.project_id,
                binding.provider,
                binding.external_repo_id,
                binding.repo_full_name,
                binding.repo_url,
                binding.status,
                unix_now() as i64
            ],
        )?;
        Ok(())
    }

    /// Looks up one cached binding by project and durable provider identity.
    pub fn get_cached_binding(
        &self,
        project_id: &str,
        provider: &str,
        external_repo_id: &str,
    ) -> Result<Option<CachedBinding>, LocalStoreError> {
        Ok(self
            .conn
            .query_row(
                "SELECT binding_id, project_id, provider, external_repo_id, repo_full_name,
                        repo_url, status, updated_at_utc
                 FROM scoped_binding_cache
                 WHERE project_id = ?1 AND provider = ?2 AND external_repo_id = ?3",
                params![project_id, provider, external_repo_id],
                |row| {
                    Ok(CachedBinding {
                        binding_id: row.get(0)?,
                        project_id: row.get(1)?,
                        provider: row.get(2)?,
                        external_repo_id: row.get(3)?,
                        repo_full_name: row.get(4)?,
                        repo_url: row.get(5)?,
                        status: row.get(6)?,
                        updated_at_utc: row.get(7)?,
                    })
                },
            )
            .optional()?)
    }

    /// Drops cached secrets and bindings for one project (context-switch
    /// cleanup). Returns the total rows removed.
    pub fn clear_scoped_cache(&self, project_id: &str) -> Result<usize, LocalStoreError> {
        self.conn.execute(
            "DELETE FROM scoped_secret_cache WHERE project_id = ?1",
            params![project_id],
        )?;
        let secrets = self.conn.changes() as usize;
        self.conn.execute(
            "DELETE FROM scoped_binding_cache WHERE project_id = ?1",
            params![project_id],
        )?;
        let bindings = self.conn.changes() as usize;
        Ok(secrets + bindings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, RecoverySecret};
    use ciphervault_format::PROTOCOL_VERSION;

    #[test]
    fn test_scoped_schema_v5_on_fresh_open() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let version: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
        let fks_on: bool = store
            .conn
            .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
            .unwrap();
        assert!(fks_on, "foreign_keys pragma must be ON");
        for table in [
            "scoped_context",
            "scoped_secret_cache",
            "scoped_binding_cache",
        ] {
            let exists: bool = store
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "missing table {table}");
        }
    }

    #[test]
    fn test_v4_to_v5_migration_recreates_scoped_tables() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        // Simulate a v4 database: drop the v5 tables, rewind the version.
        store
            .conn
            .execute_batch(
                "DROP TABLE scoped_secret_cache;
                 DROP TABLE scoped_binding_cache;
                 DROP TABLE scoped_context;
                 PRAGMA user_version = 4;",
            )
            .unwrap();
        store.run_migrations().unwrap();
        let version: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
        for table in [
            "scoped_context",
            "scoped_secret_cache",
            "scoped_binding_cache",
        ] {
            let exists: bool = store
                .conn
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                    params![table],
                    |row| row.get(0),
                )
                .unwrap();
            assert!(exists, "migration did not recreate {table}");
        }
        // Idempotent: a second run is a no-op.
        store.run_migrations().unwrap();
    }

    #[test]
    fn test_scoped_context_roundtrip() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        assert!(store.get_scoped_context().unwrap().is_none());
        store.set_scoped_context("t1", "w1", "p1", "e1").unwrap();
        let ctx = store.get_scoped_context().unwrap().unwrap();
        assert_eq!(ctx.tenant_id, "t1");
        assert_eq!(ctx.workspace_id, "w1");
        assert_eq!(ctx.project_id, "p1");
        assert_eq!(ctx.environment_id, "e1");
        // Overwrite keeps a single row.
        store.set_scoped_context("t1", "w1", "p2", "e9").unwrap();
        let ctx = store.get_scoped_context().unwrap().unwrap();
        assert_eq!(ctx.project_id, "p2");
    }

    fn cached_meta(secret_id: &str, project: &str, env: &str, name: &str) -> CachedSecretMeta {
        CachedSecretMeta {
            secret_id: secret_id.to_string(),
            tenant_id: "t1".to_string(),
            project_id: project.to_string(),
            environment_id: env.to_string(),
            repository_binding_id: None,
            service_id: None,
            name: name.to_string(),
            secret_type: "key_value".to_string(),
            current_version: 1,
            status: "active".to_string(),
            updated_at_utc: 0,
        }
    }

    #[test]
    fn test_cached_secret_upsert_and_scope_isolation() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        store
            .upsert_cached_secret(&cached_meta("s1", "p1", "e1", "DATABASE_URL"))
            .unwrap();
        // Same scope+name upserts (version bump), no duplicate row.
        let mut bumped = cached_meta("s1", "p1", "e1", "DATABASE_URL");
        bumped.current_version = 2;
        store.upsert_cached_secret(&bumped).unwrap();
        let got = store
            .get_cached_secret("p1", "e1", "DATABASE_URL")
            .unwrap()
            .unwrap();
        assert_eq!(got.current_version, 2);
        // Same name in another environment is a distinct row.
        store
            .upsert_cached_secret(&cached_meta("s2", "p1", "e2", "DATABASE_URL"))
            .unwrap();
        let other = store
            .get_cached_secret("p1", "e2", "DATABASE_URL")
            .unwrap()
            .unwrap();
        assert_eq!(other.secret_id, "s2");
        assert!(store
            .get_cached_secret("p1", "e9", "DATABASE_URL")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_cached_binding_roundtrip() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let binding = CachedBinding {
            binding_id: "b1".to_string(),
            project_id: "p1".to_string(),
            provider: "github".to_string(),
            external_repo_id: "84920194".to_string(),
            repo_full_name: "acme/pay".to_string(),
            repo_url: "https://example.invalid/acme/pay".to_string(),
            status: "active".to_string(),
            updated_at_utc: 0,
        };
        store.upsert_cached_binding(&binding).unwrap();
        let got = store
            .get_cached_binding("p1", "github", "84920194")
            .unwrap()
            .unwrap();
        assert_eq!(got.repo_full_name, "acme/pay");
        // Rename updates display fields under the same durable id.
        let mut renamed = binding;
        renamed.repo_full_name = "acme/pay-v2".to_string();
        store.upsert_cached_binding(&renamed).unwrap();
        let got = store
            .get_cached_binding("p1", "github", "84920194")
            .unwrap()
            .unwrap();
        assert_eq!(got.repo_full_name, "acme/pay-v2");
        assert!(store
            .get_cached_binding("p1", "github", "00000000")
            .unwrap()
            .is_none());
    }

    #[test]
    fn test_clear_scoped_cache_is_project_scoped() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        store
            .upsert_cached_secret(&cached_meta("s1", "p1", "e1", "A"))
            .unwrap();
        store
            .upsert_cached_secret(&cached_meta("s2", "p2", "e1", "A"))
            .unwrap();
        let removed = store.clear_scoped_cache("p1").unwrap();
        assert_eq!(removed, 1);
        assert!(store.get_cached_secret("p1", "e1", "A").unwrap().is_none());
        assert!(store.get_cached_secret("p2", "e1", "A").unwrap().is_some());
    }

    #[test]
    fn test_lease_receipt_round_trip_and_renew_upsert() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        assert!(store.list_lease_receipts().unwrap().is_empty());
        store
            .record_lease_receipt("lease-1", "https://op1", "ab", 90, 100, 1000, 2000, "sig")
            .unwrap();
        store
            .record_lease_receipt("lease-2", "https://op2", "cd", 30, 50, 1000, 1500, "sig2")
            .unwrap();
        // Soonest-expiring first.
        let listed = store.list_lease_receipts().unwrap();
        assert_eq!(listed.len(), 2);
        assert_eq!(listed[0].lease_id, "lease-2");
        assert_eq!(listed[1].lease_id, "lease-1");
        assert_eq!(listed[1].term_days, 90);
        // Renewal upserts on the lease id.
        store
            .record_lease_receipt("lease-1", "https://op1", "ab", 180, 100, 1000, 5000, "sig3")
            .unwrap();
        let listed = store.list_lease_receipts().unwrap();
        assert_eq!(listed.len(), 2);
        let renewed = listed.iter().find(|r| r.lease_id == "lease-1").unwrap();
        assert_eq!(renewed.expires_at_utc, 5000);
        assert_eq!(renewed.term_days, 180);
    }

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
    fn test_init_vault_at_epoch_resumes_recovered_epoch() {
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
            .init_vault_at_epoch(
                &vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator, 7,
            )
            .unwrap();

        // Device state resumes at epoch 7 with the recovered key; the next
        // rotation mints 8 instead of rewinding to 2.
        let (_, _, _, current_epoch) = store.get_device_state().unwrap();
        assert_eq!(current_epoch, 7);
        let fetched = store.get_epoch_key(7).unwrap();
        assert_eq!(fetched.as_bytes(), epoch_key.as_bytes());
        let (next, _) = store.rotate_epoch_key().unwrap();
        assert_eq!(next, 8);

        // Epoch 0 is rejected: it has no keys by construction.
        let store2 = LocalVaultStore::open(":memory:").unwrap();
        assert!(store2
            .init_vault_at_epoch(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator, 0)
            .is_err());
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
    fn pending_upload_summary_tracks_failure_and_completion_without_loading_rows() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        assert_eq!(
            store.pending_upload_summary().unwrap(),
            PendingUploadSummary {
                count: 0,
                failed_count: 0,
                oldest_created_at_utc: None,
            }
        );
        for (id, timestamp) in [(1u8, 300i64), (2, 100), (3, 200)] {
            store.conn.execute(
                "INSERT INTO pending_uploads(snapshot_id, record_cid, created_at_utc) VALUES(?1, ?2, ?3)",
                params![[id; 32].as_slice(), [id + 10; 32].as_slice(), timestamp],
            ).unwrap();
        }
        store
            .record_upload_failure(&[2; 32], "synthetic retry failure")
            .unwrap();
        store
            .record_upload_failure(&[2; 32], "synthetic second failure")
            .unwrap();
        assert_eq!(
            store.pending_upload_summary().unwrap(),
            PendingUploadSummary {
                count: 3,
                failed_count: 1,
                oldest_created_at_utc: Some(100),
            }
        );
        store.mark_upload_completed(&[2; 32]).unwrap();
        assert_eq!(
            store.pending_upload_summary().unwrap(),
            PendingUploadSummary {
                count: 2,
                failed_count: 0,
                oldest_created_at_utc: Some(200),
            }
        );
    }

    #[test]
    fn test_latest_sync_success_reports_newest_ok_only() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        assert!(store.latest_sync_success().unwrap().is_none());
        store
            .record_activity("WATCH_SYNC_FAILED", "boom", "{}")
            .unwrap();
        store
            .record_activity("PUSH_OK", "first", r#"{"snapshot_id":"aa"}"#)
            .unwrap();
        store
            .record_activity("WATCH_SYNC_OK", "second", r#"{"snapshot_id":"bb"}"#)
            .unwrap();
        let latest = store.latest_sync_success().unwrap().unwrap();
        assert_eq!(latest.event_type, "WATCH_SYNC_OK");
        assert!(latest.details_json.contains("bb"));
    }

    #[test]
    fn test_latest_key_backup_is_none_until_recorded() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        assert!(store.latest_key_backup().unwrap().is_none());
        store.record_activity("PUSH_OK", "snapshot", "{}").unwrap();
        assert!(store.latest_key_backup().unwrap().is_none());
        store
            .record_activity(
                "KEYBACKUP_OK",
                "sealed backup",
                r#"{"locator":"cc","replicas":2}"#,
            )
            .unwrap();
        let latest = store.latest_key_backup().unwrap().unwrap();
        assert!(latest.details_json.contains("cc"));
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
        let older = store.get_head_for_snapshot(&[0xAA; 32]).unwrap().unwrap();
        assert_eq!(older.device_counter, 1);
        older.verify(dev_sk.verifying_key().as_bytes()).unwrap();
        assert_eq!(
            store.get_head_for_snapshot(&[0xBB; 32]).unwrap().unwrap(),
            head2
        );
        assert!(store.get_head_for_snapshot(&[0xCC; 32]).unwrap().is_none());
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
    fn certified_hardware_recovery_set_is_valid_and_immutable() {
        use ciphervault_crypto::{HardwareSecurityModule, HsmSlot, SoftwareHsmSimulator};
        use ciphervault_format::{compute_digest, EpochEnvelope, SnapshotManifest};
        let store = LocalVaultStore::open(":memory:").unwrap();
        let recovery = RecoverySecret::generate();
        let root_signer = recovery.derive_recovery_signing_key().unwrap();
        let (recovery_enc_sk, recovery_enc_pk) =
            recovery.derive_recovery_encryption_keys().unwrap();
        let vault = [41; 32];
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            recovery_signing_pk: root_signer.verifying_key().to_bytes().to_vec(),
            recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0; 32],
            created_at_utc: 1,
            creation_nonce: vec![0; 32],
            signature: vec![],
        };
        genesis.sign(&root_signer).unwrap();
        let epoch_key = VaultEpochKey::generate();
        store
            .init_vault(
                &vault,
                &genesis,
                &generate_signing_key(),
                &[42; 32],
                &epoch_key,
                &recovery.derive_recovery_locator().unwrap(),
            )
            .unwrap();
        let hsm = SoftwareHsmSimulator::from_seeds(&[43; 32], &[44; 32]);
        let public_key: [u8; 32] = hsm
            .get_public_key(HsmSlot::DigitalSignature)
            .unwrap()
            .try_into()
            .unwrap();
        assert!(store
            .validate_capture_authority_for_key(&public_key, 3)
            .is_err());
        assert!(store.list_snapshots().unwrap().is_empty());
        let mut certificate = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            certificate_id: vec![45; 32],
            device_signing_pk: public_key.to_vec(),
            permissions: 1,
            authority_generation: 3,
            issued_at_utc: 1,
            signature: vec![],
        };
        certificate.sign(&root_signer).unwrap();
        store.save_device_certificate(&certificate).unwrap();
        store
            .validate_capture_authority_for_key(&public_key, 3)
            .unwrap();
        let manifest = SnapshotManifest {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            epoch: 1,
            snapshot_id: vec![46; 32],
            files: vec![],
        };
        let aad = [
            b"CipherVault-Manifest:".as_slice(),
            vault.as_slice(),
            &1u64.to_le_bytes(),
        ]
        .concat();
        let encrypted = ciphervault_crypto::encrypt_chunk(
            &epoch_key.derive_manifest_key(1).unwrap(),
            &to_canonical_cbor(&manifest).unwrap(),
            &aad,
        )
        .unwrap();
        let mut record = SnapshotRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            snapshot_id: manifest.snapshot_id.clone(),
            parent_snapshot_ids: vec![],
            device_id: vec![42; 32],
            device_counter: 1,
            authority_generation: 3,
            epoch: 1,
            encrypted_manifest_cid: compute_digest(&encrypted).to_vec(),
            encrypted_manifest_len: encrypted.len() as u64,
            advisory_timestamp_utc: 1,
            signature: vec![],
        };
        record
            .sign_with_hsm(&hsm, HsmSlot::DigitalSignature)
            .unwrap();
        store.save_snapshot(&record, &encrypted, &[]).unwrap();
        assert!(
            store.prepare_recovery_set(&record).is_err(),
            "Software key must not authorize a hardware record"
        );
        let set = store
            .prepare_recovery_set_with_hsm(&record, &hsm, HsmSlot::DigitalSignature)
            .unwrap();
        let envelope: EpochEnvelope = from_canonical_cbor(&set.records[2]).unwrap();
        envelope.verify(&public_key).unwrap();
        assert_eq!(
            ciphervault_crypto::open_sealed_box(
                &recovery_enc_sk,
                &recovery_enc_pk,
                &envelope.sealed_epoch_key
            )
            .unwrap(),
            epoch_key.as_bytes()
        );
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault.to_vec(),
            snapshot_id: record.compute_record_cid().unwrap().to_vec(),
            parent_snapshot_ids: vec![],
            closure_digest: set.closure.compute_base_closure_digest().unwrap().to_vec(),
            device_id: vec![42; 32],
            device_counter: 1,
            signature: vec![],
        };
        head.sign_with_hsm(&hsm, HsmSlot::DigitalSignature).unwrap();
        let mut discovery = set.records.clone();
        discovery.push(to_canonical_cbor(&head).unwrap());
        let (selected, cert) = ciphervault_recovery::trust::select_head(
            &discovery,
            &vault,
            root_signer.verifying_key().as_bytes(),
        )
        .unwrap();
        ciphervault_recovery::trust::verify_snapshot(&record, &selected, &cert).unwrap();
        ciphervault_recovery::trust::select_envelope(
            &discovery,
            &record,
            &cert,
            recovery_enc_pk.as_bytes(),
        )
        .unwrap();
        let again = store
            .prepare_recovery_set_with_hsm(&record, &hsm, HsmSlot::DigitalSignature)
            .unwrap();
        let legacy_retry = store.prepare_recovery_set(&record).unwrap();
        assert_eq!(
            to_canonical_cbor(&set).unwrap(),
            to_canonical_cbor(&again).unwrap()
        );
        assert_eq!(
            to_canonical_cbor(&set).unwrap(),
            to_canonical_cbor(&legacy_retry).unwrap()
        );
        assert_eq!(store.recovery_objects(&set).unwrap().len(), 5);
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
        assert_eq!(version, 5);
        let infos = store.list_epoch_keys().unwrap();
        assert_eq!(infos.len(), 1);
        assert_eq!(infos[0].created_at_utc, 0);
    }

    #[test]
    fn test_open_read_only_never_writes() {
        let path = std::env::temp_dir().join(format!(
            "cv-readonly-{}.db",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        assert!(LocalVaultStore::open_read_only(&path).is_err());
        {
            let _rw = LocalVaultStore::open(&path).unwrap();
        }
        let before = std::fs::read(&path).unwrap();
        {
            let store = LocalVaultStore::open_read_only(&path).unwrap();
            let version: u32 = store
                .conn
                .query_row("PRAGMA user_version", [], |row| row.get(0))
                .unwrap();
            assert_eq!(version, 5);
            assert!(store
                .conn
                .execute("CREATE TABLE probe_readonly(x)", [])
                .is_err());
        }
        let after = std::fs::read(&path).unwrap();
        assert_eq!(before, after);
        std::fs::remove_file(&path).ok();
    }
}
