use anyhow::{bail, Result};
use colored::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ciphervault_format::{to_canonical_cbor, HeadRecord, PROTOCOL_VERSION};
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
            bail!(
                "Vault database not found at {}. Run 'ciphervault init' first.",
                db_path.display()
            );
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

        self.store
            .save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
        self.store.increment_device_counter()?;

        let kit = OfflineRecoveryKit::parse_from_printable(&fs::read_to_string(
            self.config
                .root_dir
                .join(".ciphervault/recovery_kit_backup.txt"),
        )?)?;
        let recovery_set = self.store.prepare_recovery_set(&output.record, &kit)?;
        let record_cid = output.record.compute_record_cid()?;

        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            snapshot_id: record_cid.to_vec(),
            parent_snapshot_ids: output.record.parent_snapshot_ids.clone(),
            closure_digest: recovery_set.closure.compute_base_closure_digest()?.to_vec(),
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
            let wire_objects = self.store.recovery_objects(&recovery_set)?;
            pool.replicate_and_verify(
                &vault_id,
                &device_sk,
                &wire_objects,
                &recovery_set.closure.compute_base_closure_digest()?,
                recovery_set.closure.total_bytes,
                90,
                &recovery_set.locator,
                &to_canonical_cbor(&head)?,
                &recovery_set.records,
                3,
            )
            .await?;
            println!("Agent: Complete recovery set verified on three operators");
        }

        Ok(record_cid)
    }

    /// Runs the debounced watcher loop until shutdown signal.
    pub async fn run_loop(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        println!(
            "{}",
            "Agent watcher loop started (polling with debounce)."
                .bold()
                .green()
        );
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
