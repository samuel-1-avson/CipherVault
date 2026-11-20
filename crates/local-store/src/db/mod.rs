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

/// One entry in the tamper-evident agent-access audit chain. Records
/// what an AI agent's tools did around secrets (blocked reads, approval
/// requests, scrubbed results) — paths and decisions, never contents.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentAuditEntry {
    pub id: i64,
    pub created_at_utc: i64,
    pub tool: String,
    pub decision: String,
    pub path: String,
    pub detail_json: String,
    pub prev_hash: String,
    pub entry_hash: String,
    pub signature: String,
}

/// Result of walking the agent-audit chain from genesis.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AgentAuditReport {
    pub ok: bool,
    pub entries: usize,
    pub head_hash: String,
    pub first_bad_id: Option<i64>,
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
        let conn = Connection::open(&db_path)?;
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
        // Lock the database (and WAL/SHM sidecars) down to the current
        // user. Best-effort with a loud warning: existing vaults on
        // filesystems without ACL support must keep opening, but the
        // operator should know the metadata store is not private.
        let path = db_path.as_ref();
        if path.to_string_lossy() != ":memory:" {
            for candidate in [
                path.to_path_buf(),
                path.with_extension("db-wal"),
                path.with_extension("db-shm"),
            ] {
                if candidate.exists() {
                    if let Err(err) = ciphervault_file_lock::lock_secret_file(&candidate) {
                        eprintln!(
                            "WARNING: could not restrict permissions on {}: {err}.                              Vault metadata may be readable by other local users.",
                            candidate.display()
                        );
                    }
                }
            }
            if let Some(parent) = path.parent() {
                let _ = ciphervault_file_lock::lock_secret_directory(parent);
            }
        }
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

            CREATE TABLE IF NOT EXISTS agent_audit (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at_utc INTEGER NOT NULL,
                tool TEXT NOT NULL,
                decision TEXT NOT NULL,
                path TEXT NOT NULL DEFAULT '',
                detail_json TEXT NOT NULL DEFAULT '{}',
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL,
                signature TEXT NOT NULL
            );

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

    /// Reads snapshot metadata by its record CID without loading the manifest.
    pub fn get_snapshot_record(
        &self,
        record_cid: &[u8; 32],
    ) -> Result<Option<SnapshotRecord>, LocalStoreError> {
        let bytes: Option<Vec<u8>> = self
            .conn
            .query_row(
                "SELECT record_cbor FROM snapshots WHERE snapshot_id = ?1",
                params![record_cid.as_slice()],
                |row| row.get(0),
            )
            .optional()?;
        Ok(bytes.as_deref().map(from_canonical_cbor).transpose()?)
    }

    /// Derives the deterministic anchor salt for a snapshot head from its
    /// epoch key. The salt is recoverable by the vault owner (epoch keys
    /// replicate inside sealed recovery records) without any new network
    /// calls, so on-chain commitments stay verifiable after local state
    /// loss. Fails when the snapshot or its epoch key is unknown locally —
    /// callers fall back to a one-time local salt for such legacy heads.
    pub fn derive_head_anchor_salt(
        &self,
        head_cid: &[u8; 32],
    ) -> Result<[u8; 32], LocalStoreError> {
        let (record, _) = self.get_snapshot(head_cid)?;
        let epoch_key = self.get_epoch_key(record.epoch)?;
        Ok(epoch_key.derive_anchor_salt(head_cid)?)
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
}

mod activity;
mod retention;
mod scoped;
#[cfg(test)]
mod tests;

pub use scoped::{CachedBinding, CachedSecretMeta, ScopedContext};
