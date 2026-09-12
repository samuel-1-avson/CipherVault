use anyhow::{bail, Result};
use chrono::Utc;
use colored::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use x25519_dalek::PublicKey as X25519PublicKey;

use ciphervault_crypto::seal_box;
use ciphervault_format::{
    compute_digest, to_canonical_cbor, EpochEnvelope, HeadRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_recovery::OfflineRecoveryKit;
use ciphervault_snapshot::create_snapshot;
use ciphervault_storage::MultiOperatorPool;

/// Configuration for the background watcher agent.
#[derive(Clone, Debug)]
pub struct WatcherConfig {
    pub root_dir: PathBuf,
    pub debounce: Duration,
    pub replicate_remote: bool,
    pub operators: Vec<String>,
}

/// In-memory cache of file content digests to avoid redundant snapshots.
#[derive(Default)]
pub struct FileHashCache {
    hashes: HashMap<PathBuf, [u8; 32]>,
}

pub struct VaultWatcher {
    config: WatcherConfig,
    store: LocalVaultStore,
    hash_cache: Arc<Mutex<FileHashCache>>,
}

impl VaultWatcher {
    pub fn new(config: WatcherConfig) -> Result<Self> {
        let db_path = config.root_dir.join(".ciphervault").join("vault.db");
        if !db_path.exists() {
            bail!("Vault database not found at {}. Run 'ciphervault init' first.", db_path.display());
        }
        let store = LocalVaultStore::open(db_path)?;
        Ok(Self {
            config,
            store,
            hash_cache: Arc::new(Mutex::new(FileHashCache::default())),
        })
    }

    /// Performs a coherent read of a tracked file:
    /// verifies that size and modification time match before and after reading.
    pub fn read_file_coherently<P: AsRef<Path>>(path: P) -> Result<Option<Vec<u8>>> {
        let p = path.as_ref();
        if !p.exists() {
            return Ok(None);
        }

        let pre_meta = fs::metadata(p)?;
        let data = fs::read(p)?;
        let post_meta = fs::metadata(p)?;

        if pre_meta.len() != post_meta.len() {
            return Ok(None); // File changed during read; abort for this tick
        }

        if let (Ok(pre_m), Ok(post_m)) = (pre_meta.modified(), post_meta.modified()) {
            if pre_m != post_m {
                return Ok(None); // Modified mid-read
            }
        }

        Ok(Some(data))
    }

    /// Checks all tracked files for coherent modifications.
    /// Returns true if any tracked file differs from our cache.
    pub fn check_for_changes(&self) -> Result<bool> {
        let tracked = self.store.list_tracked_files()?;
        let mut changed = false;
        let mut cache = self.hash_cache.lock().unwrap();

        for (rel_path, _) in &tracked {
            let full_path = self.config.root_dir.join(rel_path);
            let maybe_data = Self::read_file_coherently(&full_path)?;

            match maybe_data {
                Some(bytes) => {
                    let mut hasher = Sha256::new();
                    hasher.update(&bytes);
                    let digest: [u8; 32] = hasher.finalize().into();

                    let prev = cache.hashes.get(rel_path);
                    if prev != Some(&digest) {
                        changed = true;
                        cache.hashes.insert(rel_path.clone(), digest);
                    }
                }
                None => {
                    // File does not exist or modified mid-read
                    if cache.hashes.remove(rel_path).is_some() {
                        changed = true;
                    }
                }
            }
        }

        Ok(changed)
    }

    /// Triggers snapshot creation and optional multi-operator replication.
    pub async fn capture_and_sync(&self, _message: Option<String>) -> Result<[u8; 32]> {
        let vault_id = self.store.get_vault_id()?;
        let (device_id, device_sk, counter, epoch) = self.store.get_device_state()?;
        let epoch_key = self.store.get_epoch_key(epoch)?;
        let tracked = self.store.list_tracked_files()?;

        let active_head = self.store.get_active_head()?;
        let parent_ids = match active_head {
            Some(ref h) => vec![{
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h.snapshot_id);
                arr
            }],
            None => Vec::new(),
        };

        println!("{}", "Agent: Capturing new snapshot...".cyan());

        let output = create_snapshot(
            &self.config.root_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids,
            &device_id,
            counter + 1,
            1,
            &device_sk,
        )?;

        self.store.save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
        self.store.increment_device_counter()?;

        let record_cid = output.record.compute_record_cid()?;

        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            snapshot_id: record_cid.to_vec(),
            parent_snapshot_ids: output.record.parent_snapshot_ids.clone(),
            closure_digest: output.closure.compute_base_closure_digest()?.to_vec(),
            device_id: device_id.to_vec(),
            device_counter: counter + 1,
            signature: Vec::new(),
        };
        head.sign(&device_sk)?;
        self.store.set_head(&head)?;

        let snapshot_hex = hex::encode(&output.record.snapshot_id);
        println!(
            "{} Snapshot {} captured ({} files, {} chunks)",
            "Agent:".green().bold(),
            snapshot_hex.yellow(),
            tracked.len(),
            output.chunks.len()
        );

        if self.config.replicate_remote && !self.config.operators.is_empty() {
            println!(
                "Agent: Replicating across {} operators in background...",
                self.config.operators.len()
            );

            let pool = MultiOperatorPool::new(self.config.operators.clone());
            let mut wire_objects = Vec::new();
            for chunk in &output.chunks {
                let cid = chunk.compute_cid()?;
                let cbor = to_canonical_cbor(chunk)?;
                wire_objects.push((cid, cbor));
            }
            wire_objects.push((output.manifest_cid, output.encrypted_manifest.clone()));
            wire_objects.push((record_cid, to_canonical_cbor(&output.record)?));

            let kit_path = self.config.root_dir.join(".ciphervault").join("recovery_kit_backup.txt");
            let mut recovery_locator = [0u8; 32];
            let mut envelope_bytes = Vec::new();
            if kit_path.exists() {
                if let Ok(kit_txt) = fs::read_to_string(&kit_path) {
                    if let Ok(kit) = OfflineRecoveryKit::parse_from_printable(&kit_txt) {
                        if let Ok(enc_pk_bytes) = hex::decode(&kit.recovery_encryption_pk_hex) {
                            let mut epk_arr = [0u8; 32];
                            epk_arr.copy_from_slice(&enc_pk_bytes);
                            let enc_pk = X25519PublicKey::from(epk_arr);
                            if let Ok(sealed) = seal_box(&enc_pk, epoch_key.as_bytes()) {
                                let mut envelope = EpochEnvelope {
                                    version: PROTOCOL_VERSION,
                                    vault_id: vault_id.to_vec(),
                                    epoch,
                                    recipient_fingerprint: enc_pk.as_bytes().to_vec(),
                                    sealed_epoch_key: sealed,
                                    created_at_utc: Utc::now().timestamp() as u64,
                                    signer_device_id: device_id.to_vec(),
                                    signature: Vec::new(),
                                };
                                let _ = envelope.sign(&device_sk);
                                if let Ok(cbor) = to_canonical_cbor(&envelope) {
                                    let env_cid = compute_digest(&cbor);
                                    wire_objects.push((env_cid, cbor.clone()));
                                    envelope_bytes = cbor;
                                }
                            }
                        }
                        if let Ok(loc_bytes) = hex::decode(&kit.recovery_locator_hex) {
                            recovery_locator.copy_from_slice(&loc_bytes);
                        }
                    }
                }
            }

            let head_cbor = to_canonical_cbor(&head)?;
            let closure_digest = output.closure.compute_base_closure_digest()?;

            let rep_result = pool
                .replicate_and_verify(
                    &vault_id,
                    &device_sk,
                    &wire_objects,
                    &closure_digest,
                    output.closure.total_bytes,
                    90,
                    &recovery_locator,
                    &head_cbor,
                    1,
                )
                .await;

            if !envelope_bytes.is_empty() {
                let sessions = pool.authenticate_all(&vault_id, &device_sk).await;
                for (client, token) in sessions {
                    let _ = client.append_recovery_record(&token, &recovery_locator, envelope_bytes.clone()).await;
                }
            }

            match rep_result {
                Ok(receipts) => {
                    println!(
                        "{} Remote replication verified on {}/{} operators",
                        "Agent:".green().bold(),
                        receipts.len(),
                        self.config.operators.len()
                    );
                }
                Err(e) => {
                    eprintln!("{} Replication warning: {}", "Agent:".yellow(), e);
                }
            }
        }

        Ok(record_cid)
    }

    /// Runs the debounced watcher loop until shutdown signal.
    pub async fn run_loop(&self, mut shutdown_rx: tokio::sync::broadcast::Receiver<()>) -> Result<()> {
        println!("{}", "Agent watcher loop started (polling with debounce).".bold().green());
        let mut last_change = None;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    println!("Agent received shutdown signal. Terminating gracefully.");
                    break;
                }
                _ = tokio::time::sleep(Duration::from_millis(500)) => {
                    match self.check_for_changes() {
                        Ok(true) => {
                            last_change = Some(Instant::now());
                            println!("Agent: Detected change in tracked file. Debouncing...");
                        }
                        Ok(false) => {
                            if let Some(t) = last_change {
                                if t.elapsed() >= self.config.debounce {
                                    last_change = None;
                                    println!("Agent: Debounce window expired. Capturing coherent snapshot...");
                                    if let Err(e) = self.capture_and_sync(Some("Automated agent capture".into())).await {
                                        eprintln!("{} Failed to capture snapshot: {}", "Agent Error:".red(), e);
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("{} Error checking changes: {}", "Agent Error:".red(), e);
                        }
                    }
                }
            }
        }

        Ok(())
    }
}
