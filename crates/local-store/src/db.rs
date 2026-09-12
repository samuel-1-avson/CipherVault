use std::path::{Path, PathBuf};
use ed25519_dalek::SigningKey;
use rand::RngCore;
use rusqlite::{params, Connection};

use ciphervault_crypto::VaultEpochKey;
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, CheckpointEvidence, ChunkWireObject, DeviceCertificate,
    GenesisRecord, HeadRecord, SnapshotRecord,
};

use crate::error::LocalStoreError;

pub struct LocalVaultStore {
    conn: Connection,
}

impl LocalVaultStore {
    /// Opens or creates a local SQLite vault database at the specified file path.
    pub fn open<P: AsRef<Path>>(db_path: P) -> Result<Self, LocalStoreError> {
        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init_tables()?;
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
            "#,
        )?;
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
    ) -> Result<(), LocalStoreError> {
        let genesis_cbor = to_canonical_cbor(genesis)?;
        let device_sk_bytes = device_sk.to_bytes();

        self.conn.execute(
            r#"
            INSERT INTO vault_metadata (
                id, vault_id, current_epoch, device_id, device_counter,
                authority_generation, device_signing_key, recovery_signing_pk,
                recovery_encryption_pk, genesis_cbor
            ) VALUES (1, ?1, 1, ?2, 0, 1, ?3, ?4, ?5, ?6)
            "#,
            params![
                vault_id.as_slice(),
                device_id.as_slice(),
                device_sk_bytes.as_slice(),
                genesis.recovery_signing_pk.as_slice(),
                genesis.recovery_encryption_pk.as_slice(),
                genesis_cbor
            ],
        )?;

        self.save_epoch_key(1, initial_epoch_key)?;
        Ok(())
    }

    /// Retrieves the current vault ID.
    pub fn get_vault_id(&self) -> Result<[u8; 32], LocalStoreError> {
        let mut stmt = self.conn.prepare("SELECT vault_id FROM vault_metadata WHERE id = 1")?;
        let mut rows = stmt.query([])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&blob);
            Ok(arr)
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
            dev_id.copy_from_slice(&dev_id_blob);

            let mut sk_bytes = [0u8; 32];
            sk_bytes.copy_from_slice(&dev_sk_blob);
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
        let mut stmt = self.conn.prepare("SELECT device_counter FROM vault_metadata WHERE id = 1")?;
        let counter: u64 = stmt.query_row([], |r| r.get(0))?;
        Ok(counter)
    }

    /// Stores an epoch key.
    pub fn save_epoch_key(&self, epoch: u64, key: &VaultEpochKey) -> Result<(), LocalStoreError> {
        self.conn.execute(
            "INSERT OR REPLACE INTO epoch_keys (epoch, epoch_key_bytes) VALUES (?1, ?2)",
            params![epoch, key.as_bytes().as_slice()],
        )?;
        Ok(())
    }

    /// Retrieves an epoch key.
    pub fn get_epoch_key(&self, epoch: u64) -> Result<VaultEpochKey, LocalStoreError> {
        let mut stmt = self.conn.prepare("SELECT epoch_key_bytes FROM epoch_keys WHERE epoch = ?1")?;
        let mut rows = stmt.query(params![epoch])?;
        if let Some(row) = rows.next()? {
            let blob: Vec<u8> = row.get(0)?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&blob);
            Ok(VaultEpochKey::from_bytes(arr))
        } else {
            Err(LocalStoreError::NotFound(format!("Epoch key for epoch {}", epoch)))
        }
    }

    /// Adds or ensures tracking of a relative path, assigning a confidential random file_id.
    pub fn track_file(&self, rel_path: &str) -> Result<[u8; 32], LocalStoreError> {
        let normalized = rel_path.replace('\\', "/");
        let mut stmt = self.conn.prepare("SELECT file_id FROM tracked_files WHERE relative_path = ?1")?;
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
        let mut stmt = self.conn.prepare("SELECT relative_path, file_id FROM tracked_files ORDER BY relative_path ASC")?;
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

    /// Saves a snapshot and its chunks into the local store.
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
            .map(|p| hex::encode(p))
            .collect::<Vec<_>>()
            .join(",");

        // Primary index by content-addressed record_cid
        self.conn.execute(
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
            self.conn.execute(
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
            self.conn.execute(
                "INSERT OR REPLACE INTO local_chunks (chunk_cid, chunk_cbor) VALUES (?1, ?2)",
                params![cid.as_slice(), cbor],
            )?;
        }

        Ok(())
    }

    /// Retrieves a snapshot record by snapshot_id.
    pub fn get_snapshot(&self, snapshot_id: &[u8; 32]) -> Result<(SnapshotRecord, Vec<u8>), LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT record_cbor, encrypted_manifest FROM snapshots WHERE snapshot_id = ?1"
        )?;
        let mut rows = stmt.query(params![snapshot_id.as_slice()])?;
        if let Some(row) = rows.next()? {
            let record_cbor: Vec<u8> = row.get(0)?;
            let manifest: Vec<u8> = row.get(1)?;
            let record: SnapshotRecord = from_canonical_cbor(&record_cbor)?;
            Ok((record, manifest))
        } else {
            Err(LocalStoreError::NotFound(format!("Snapshot {}", hex::encode(snapshot_id))))
        }
    }

    /// Retrieves all snapshots in chronological order.
    pub fn list_snapshots(&self) -> Result<Vec<SnapshotRecord>, LocalStoreError> {
        let mut stmt = self.conn.prepare(
            "SELECT record_cbor FROM snapshots ORDER BY created_at_utc ASC"
        )?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let rec: SnapshotRecord = from_canonical_cbor(&blob)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e)))?;
            Ok(rec)
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
        let mut stmt = self.conn.prepare("SELECT chunk_cbor FROM local_chunks WHERE chunk_cid = ?1")?;
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
        let mut stmt = self.conn.prepare("SELECT cert_cbor FROM device_certificates")?;
        let rows = stmt.query_map([], |row| {
            let blob: Vec<u8> = row.get(0)?;
            let cert: DeviceCertificate = from_canonical_cbor(&blob)
                .map_err(|e| rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Blob, Box::new(e)))?;
            Ok(cert)
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    /// Updates the active head record.
    pub fn set_head(&self, head: &HeadRecord) -> Result<(), LocalStoreError> {
        let cbor = to_canonical_cbor(head)?;
        self.conn.execute("UPDATE heads SET is_active = 0", [])?;
        self.conn.execute(
            "INSERT OR REPLACE INTO heads (snapshot_id, head_cbor, is_active) VALUES (?1, ?2, 1)",
            params![head.snapshot_id.as_slice(), cbor],
        )?;
        Ok(())
    }

    /// Gets the current active head record.
    pub fn get_active_head(&self) -> Result<Option<HeadRecord>, LocalStoreError> {
        let mut stmt = self.conn.prepare("SELECT head_cbor FROM heads WHERE is_active = 1")?;
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
    pub fn save_checkpoint_evidence(&self, evidence: &CheckpointEvidence) -> Result<(), LocalStoreError> {
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
    pub fn get_checkpoint_evidence(&self, head_record_cid: &[u8; 32]) -> Result<Option<CheckpointEvidence>, LocalStoreError> {
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

        store.init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key).unwrap();

        let fetched_id = store.get_vault_id().unwrap();
        assert_eq!(fetched_id, vault_id);

        let file_id = store.track_file(".env").unwrap();
        let files = store.list_tracked_files().unwrap();
        assert_eq!(files.len(), 1);
        assert_eq!(files[0].0, PathBuf::from(".env"));
        assert_eq!(files[0].1, file_id);
    }

    #[test]
    fn test_checkpoint_evidence_storage() {
        let store = LocalVaultStore::open(":memory:").unwrap();
        let salt = [1u8; 32];
        let head_cid = [2u8; 32];
        let contract = [3u8; 20];
        let tx_hash = [4u8; 32];

        let evidence = CheckpointEvidence::new(salt, head_cid, 42161, contract, tx_hash, 1234567, 1700000000);
        store.save_checkpoint_evidence(&evidence).unwrap();

        let fetched = store.get_checkpoint_evidence(&head_cid).unwrap().unwrap();
        assert_eq!(fetched.commitment, evidence.commitment);
        assert_eq!(fetched.block_number, 1234567);
        assert_eq!(fetched.chain_id, 42161);
        assert!(fetched.verify_commitment());
    }
}
