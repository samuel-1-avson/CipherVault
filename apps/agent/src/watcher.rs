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
use ciphervault_snapshot::create_snapshot;
use ciphervault_storage::MultiOperatorPool;
use notify::{Config, Event, RecommendedWatcher, RecursiveMode, Watcher};

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

        let recovery_set = self.store.prepare_recovery_set(&output.record)?;
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

        let snap_id_arr: [u8; 32] = {
            let mut a = [0u8; 32];
            if output.record.snapshot_id.len() == 32 {
                a.copy_from_slice(&output.record.snapshot_id);
            }
            a
        };

        if self.config.replicate_remote && !self.config.operators.is_empty() {
            println!(
                "Agent: Replicating across {} operators in background...",
                self.config.operators.len()
            );

            let pool = MultiOperatorPool::new(self.config.operators.clone());
            let wire_objects = self.store.recovery_objects(&recovery_set)?;
            match pool
                .replicate_and_verify(
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
                .await
            {
                Ok(_) => {
                    let _ = self.store.mark_upload_completed(&snap_id_arr);
                    println!("Agent: Complete recovery set verified on three operators");
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let _ = self.store.record_upload_failure(&snap_id_arr, &err_msg);
                    return Err(e.into());
                }
            }
        } else {
            let _ = self.store.mark_upload_completed(&snap_id_arr);
        }

        Ok(record_cid)
    }

    /// Retries replication for any snapshots that were saved locally but failed remote replication.
    pub async fn retry_pending_uploads(&self) -> Result<()> {
        if !self.config.replicate_remote || self.config.operators.is_empty() {
            return Ok(());
        }

        let pending = self.store.list_pending_uploads()?;
        if pending.is_empty() {
            return Ok(());
        }

        let vault_id = self.store.get_vault_id()?;
        let (_, device_sk, _, _) = self.store.get_device_state()?;
        let pool = MultiOperatorPool::new(self.config.operators.clone());

        for item in pending {
            if let Ok((record, _)) = self.store.get_snapshot(&item.snapshot_id) {
                if let Ok(recovery_set) = self.store.prepare_recovery_set(&record) {
                    if let Ok(wire_objects) = self.store.recovery_objects(&recovery_set) {
                        if let Ok(Some(head)) = self.store.get_active_head() {
                            if let Ok(closure_digest) =
                                recovery_set.closure.compute_base_closure_digest()
                            {
                                if let Ok(head_cbor) = to_canonical_cbor(&head) {
                                    match pool
                                        .replicate_and_verify(
                                            &vault_id,
                                            &device_sk,
                                            &wire_objects,
                                            &closure_digest,
                                            recovery_set.closure.total_bytes,
                                            90,
                                            &recovery_set.locator,
                                            &head_cbor,
                                            &recovery_set.records,
                                            3,
                                        )
                                        .await
                                    {
                                        Ok(_) => {
                                            let _ =
                                                self.store.mark_upload_completed(&item.snapshot_id);
                                            println!(
                                                "Agent: Retry succeeded for pending snapshot {}",
                                                hex::encode(item.snapshot_id)
                                            );
                                        }
                                        Err(e) => {
                                            let _ = self.store.record_upload_failure(
                                                &item.snapshot_id,
                                                &e.to_string(),
                                            );
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        Ok(())
    }

    /// Runs the debounced watcher loop until shutdown signal.
    pub async fn run_loop(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        println!(
            "{} {}",
            "[WATCH]".bold().cyan(),
            format!(
                "Autonomous watcher active on '{}' (debounce: {}s, sync: {})",
                self.config.root_dir.display(),
                self.config.debounce.as_secs(),
                if self.config.replicate_remote {
                    "3/3 operators"
                } else {
                    "local-only"
                }
            )
            .green()
        );

        let tracked = self.store.list_tracked_files()?;
        println!(
            "{} Monitoring {} tracked confidential file(s):",
            "[WATCH]".bold().cyan(),
            tracked.len()
        );
        for (f, _) in &tracked {
            println!("  - {}", f.display().to_string().yellow());
        }

        // Initialize file hash cache on startup
        let _ = self.check_for_changes();

        // Setup notify OS event watcher
        let (event_tx, mut event_rx) =
            tokio::sync::mpsc::unbounded_channel::<notify::Result<Event>>();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                let _ = event_tx.send(res);
            },
            Config::default(),
        )?;

        if let Err(e) = watcher.watch(&self.config.root_dir, RecursiveMode::Recursive) {
            eprintln!(
                "{} Could not attach recursive OS event hook ({}); falling back to interval polling.",
                "[WARN]".bold().yellow(),
                e
            );
        } else {
            println!(
                "{} Native OS filesystem event hook active (ReadDirectoryChangesW/inotify).",
                "[WATCH]".bold().cyan()
            );
        }

        let mut last_change: Option<(Instant, String)> = None;
        let mut last_poll = Instant::now();

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    println!("\n{} Shutdown signal received. Terminating watcher cleanly.", "[WATCH]".bold().cyan());
                    break;
                }

                Some(event_res) = event_rx.recv() => {
                    if let Ok(event) = event_res {
                        let tracked_now = self.store.list_tracked_files().unwrap_or_default();
                        let mut matched = None;
                        for p in &event.paths {
                            if is_ignored_path(p) {
                                continue;
                            }
                            for (rel, _) in &tracked_now {
                                if is_path_matching_tracked(p, rel, &self.config.root_dir) {
                                    matched = Some(rel.to_string_lossy().to_string());
                                    break;
                                }
                            }
                            if matched.is_some() {
                                break;
                            }
                        }

                        if let Some(filename) = matched {
                            last_change = Some((Instant::now(), filename.clone()));
                            println!(
                                "{} [{}] Detected save event on '{}'. Debouncing ({:.1}s)...",
                                "[WATCH]".bold().cyan(),
                                chrono::Local::now().format("%H:%M:%S").to_string().dimmed(),
                                filename.yellow(),
                                self.config.debounce.as_secs_f32()
                            );
                        }
                    }
                }

                _ = tokio::time::sleep(Duration::from_millis(150)) => {
                    // 1. Check if debounce window has expired
                    if let Some((t, ref changed_file)) = last_change {
                        if t.elapsed() >= self.config.debounce {
                            let target_name = changed_file.clone();
                            last_change = None;

                            println!(
                                "{} [{}] Debounce window expired. Verifying coherent digest for '{}'...",
                                "[WATCH]".bold().cyan(),
                                chrono::Local::now().format("%H:%M:%S").to_string().dimmed(),
                                target_name.yellow()
                            );

                            match self.check_for_changes() {
                                Ok(true) => {
                                    println!(
                                        "{} Content changed. Creating encrypted FastCDC snapshot...",
                                        "[SNAPSHOT]".bold().green()
                                    );
                                    let commit_msg = format!("Auto-snapshot: updated {}", target_name);
                                    match self.capture_and_sync(Some(commit_msg)).await {
                                        Ok(cid) => {
                                            let cid_short = hex::encode(&cid[..8]);
                                            println!(
                                                "{} [{}] Snapshot commit {} created & verified!",
                                                "[SNAPSHOT]".bold().green(),
                                                chrono::Local::now().format("%H:%M:%S").to_string().dimmed(),
                                                cid_short.yellow()
                                            );
                                        }
                                        Err(e) => {
                                            eprintln!(
                                                "{} Snapshot capture failed: {}",
                                                "[ERROR]".bold().red(),
                                                e
                                            );
                                        }
                                    }
                                }
                                Ok(false) => {
                                    println!(
                                        "{} File touch detected but content identical. Skipped redundant snapshot.",
                                        "[WATCH]".bold().dimmed()
                                    );
                                }
                                Err(e) => {
                                    eprintln!("{} Hash check error: {}", "[ERROR]".bold().red(), e);
                                }
                            }
                        }
                    }

                    // 2. Periodic background check & retry (every 3 seconds)
                    if last_change.is_none() && last_poll.elapsed() >= Duration::from_secs(3) {
                        last_poll = Instant::now();

                        // Retry any previously failed uploads
                        let _ = self.retry_pending_uploads().await;

                        // Fallback check in case an OS event was dropped by the kernel
                        if let Ok(true) = self.check_for_changes() {
                            println!(
                                "{} [{}] Detected un-snapshotted change via fallback check. Debouncing...",
                                "[WATCH]".bold().cyan(),
                                chrono::Local::now().format("%H:%M:%S").to_string().dimmed()
                            );
                            last_change = Some((Instant::now(), "tracked files".into()));
                        }
                    }
                }
            }
        }

        Ok(())
    }
}

fn is_path_matching_tracked(event_path: &Path, rel_path: &Path, root_dir: &Path) -> bool {
    let target = root_dir.join(rel_path);
    if event_path == target {
        return true;
    }
    if let (Ok(c1), Ok(c2)) = (event_path.canonicalize(), target.canonicalize()) {
        if c1 == c2 {
            return true;
        }
    }
    let event_str = event_path.to_string_lossy().replace('\\', "/");
    let rel_str = rel_path.to_string_lossy().replace('\\', "/");
    event_str.ends_with(&rel_str)
}

fn is_ignored_path(path: &Path) -> bool {
    let s = path.to_string_lossy();
    s.contains(".git") || s.contains(".ciphervault") || s.contains("target")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_path_matching_tracked() {
        let root = Path::new("/workspace");
        let tracked = Path::new(".env");
        let event = Path::new("/workspace/.env");
        assert!(is_path_matching_tracked(event, tracked, root));

        let sub_tracked = Path::new("config/secrets.json");
        let sub_event = Path::new("/workspace/config/secrets.json");
        assert!(is_path_matching_tracked(sub_event, sub_tracked, root));

        let other = Path::new("/workspace/src/main.rs");
        assert!(!is_path_matching_tracked(other, tracked, root));
    }

    #[test]
    fn test_is_ignored_path() {
        assert!(is_ignored_path(Path::new("/workspace/.git/HEAD")));
        assert!(is_ignored_path(Path::new("/workspace/.ciphervault/vault.db")));
        assert!(is_ignored_path(Path::new("/workspace/target/debug/app")));
        assert!(!is_ignored_path(Path::new("/workspace/.env")));
        assert!(!is_ignored_path(Path::new("/workspace/config/key.pem")));
    }
}
