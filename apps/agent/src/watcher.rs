use anyhow::{bail, Context, Result};
use colored::*;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use zeroize::Zeroizing;

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
    /// Inspector mode: report captures without persisting or replicating anything.
    pub dry_run: bool,
}

/// Inspector report: what a watcher capture would do, computed without
/// persisting anything (R15 dry-run mode).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchInspection {
    pub files: usize,
    pub chunks: usize,
    pub bytes: u64,
    pub would_replicate: bool,
    pub operator_count: usize,
}

/// In-memory cache of file content digests to avoid redundant snapshots.
#[derive(Default)]
pub struct FileHashCache {
    hashes: HashMap<PathBuf, Option<[u8; 32]>>,
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
        let mut baseline = FileHashCache::default();
        if let Some(head) = store.get_active_head()? {
            let id: [u8; 32] = head
                .snapshot_id
                .as_slice()
                .try_into()
                .context("Invalid snapshot head")?;
            let (record, encrypted) = store.get_snapshot(&id)?;
            let key = store.get_epoch_key(record.epoch)?;
            let aad = [
                b"CipherVault-Manifest:",
                record.vault_id.as_slice(),
                &record.epoch.to_le_bytes(),
            ]
            .concat();
            let manifest_key = Zeroizing::new(key.derive_manifest_key(record.epoch)?);
            let plaintext = Zeroizing::new(ciphervault_crypto::decrypt_chunk(
                &manifest_key,
                &encrypted,
                &aad,
            )?);
            let manifest: ciphervault_format::SnapshotManifest =
                ciphervault_format::from_canonical_cbor(&plaintext)?;
            for file in &manifest.files {
                let digest = if file.is_deleted {
                    None
                } else {
                    Some(
                        file.plaintext_sha256
                            .as_slice()
                            .try_into()
                            .context("Invalid captured digest")?,
                    )
                };
                baseline
                    .hashes
                    .insert(PathBuf::from(&file.relative_path), digest);
            }
        }
        Ok(Self {
            config,
            store,
            hash_cache: Arc::new(Mutex::new(baseline)),
        })
    }

    /// Performs a coherent read of a tracked file:
    /// verifies that size and modification time match before and after reading.
    pub fn read_file_coherently<P: AsRef<Path>>(path: P) -> Result<Option<Vec<u8>>> {
        let p = path.as_ref();
        validate_no_links(p)?;
        let pre_meta = match fs::symlink_metadata(p) {
            Ok(meta) => meta,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if pre_meta.file_type().is_symlink() || !pre_meta.is_file() {
            bail!("Tracked path is not a regular file: {}", p.display());
        }
        if pre_meta.len() > ciphervault_snapshot::MAX_FILE_SIZE {
            bail!(
                "Tracked file exceeds the capture size limit: {}",
                p.display()
            );
        }
        let mut file = ciphervault_file_lock::open_regular_file(p)?;
        let opened_pre_meta = file.metadata()?;
        if opened_pre_meta.len() > ciphervault_snapshot::MAX_FILE_SIZE {
            bail!(
                "Tracked file exceeds the capture size limit: {}",
                p.display()
            );
        }
        let mut data = Zeroizing::new(Vec::with_capacity(opened_pre_meta.len() as usize));
        (&mut file)
            .take(ciphervault_snapshot::MAX_FILE_SIZE + 1)
            .read_to_end(&mut data)?;
        let opened_post_meta = file.metadata()?;
        validate_no_links(p)?;
        let post_meta = fs::symlink_metadata(p)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if pre_meta.dev() != opened_pre_meta.dev()
                || pre_meta.ino() != opened_pre_meta.ino()
                || post_meta.dev() != opened_post_meta.dev()
                || post_meta.ino() != opened_post_meta.ino()
            {
                bail!("Tracked file was replaced during hashing: {}", p.display());
            }
        }
        if data.len() as u64 > ciphervault_snapshot::MAX_FILE_SIZE
            || pre_meta.len() != post_meta.len()
            || pre_meta.modified()? != post_meta.modified()?
            || opened_pre_meta.len() != opened_post_meta.len()
            || opened_pre_meta.modified()? != opened_post_meta.modified()?
            || post_meta.len() != opened_post_meta.len()
            || post_meta.modified()? != opened_post_meta.modified()?
            || !post_meta.is_file()
        {
            bail!("Tracked file changed during hashing: {}", p.display());
        }
        Ok(Some(std::mem::take(&mut *data)))
    }

    /// Detect changes against the committed snapshot. Detection never acknowledges
    /// bytes: a failed capture and a second fallback scan must still see them.
    pub fn check_for_changes(&self) -> Result<bool> {
        let tracked = self.store.list_tracked_files()?;
        let cache = self
            .hash_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Watcher cache lock failed"))?;
        for (rel_path, _) in &tracked {
            ciphervault_snapshot::validate_safe_relative_path(&rel_path.to_string_lossy())?;
            let maybe_data = Self::read_file_coherently(self.config.root_dir.join(rel_path))?;
            let digest = maybe_data.map(|bytes| {
                let bytes = Zeroizing::new(bytes);
                let digest: [u8; 32] = Sha256::digest(&*bytes).into();
                digest
            });
            if cache.hashes.get(rel_path) != Some(&digest) {
                return Ok(true);
            }
        }
        Ok(false)
    }

    fn acknowledge_capture(&self, hashes: &[(PathBuf, Option<[u8; 32]>)]) -> Result<()> {
        let mut cache = self
            .hash_cache
            .lock()
            .map_err(|_| anyhow::anyhow!("Watcher cache lock failed"))?;
        cache.hashes = hashes.iter().cloned().collect();
        Ok(())
    }

    /// Builds the pending snapshot in memory and reports what a capture
    /// would do. Persists nothing, touches no counters, replicates nothing.
    pub fn inspect_pending_capture(&self) -> Result<WatchInspection> {
        let vault_id = self.store.get_vault_id()?;
        let (device_id, device_sk, counter, epoch) = self.store.get_device_state()?;
        let epoch_key = self.store.get_epoch_key(epoch)?;
        let tracked = self.store.list_tracked_files()?;
        let authority_generation = self
            .store
            .latest_capture_authority_for_key(&device_sk.verifying_key().to_bytes())?
            .authority_generation;

        let active_head = self.store.get_active_head()?;
        let parent_ids = match active_head {
            Some(ref h) => vec![{
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&h.snapshot_id);
                arr
            }],
            None => Vec::new(),
        };

        let output = create_snapshot(
            &self.config.root_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids,
            &device_id,
            counter + 1,
            authority_generation,
            &device_sk,
        )?;
        let bytes: u64 = output
            .chunks
            .iter()
            .map(|chunk| chunk.payload.len() as u64)
            .sum();
        if self.config.dry_run {
            self.acknowledge_capture(&output.captured_file_hashes)?;
        }
        Ok(WatchInspection {
            files: tracked.len(),
            chunks: output.chunks.len(),
            bytes,
            would_replicate: self.config.replicate_remote && !self.config.operators.is_empty(),
            operator_count: self.config.operators.len(),
        })
    }

    /// Triggers snapshot creation and optional multi-operator replication.
    pub async fn capture_and_sync(&self, _message: Option<String>) -> Result<[u8; 32]> {
        let vault_id = self.store.get_vault_id()?;
        let (device_id, device_sk, counter, epoch) = self.store.get_device_state()?;
        let epoch_key = self.store.get_epoch_key(epoch)?;
        let tracked = self.store.list_tracked_files()?;
        let authority_generation = self
            .store
            .latest_capture_authority_for_key(&device_sk.verifying_key().to_bytes())?
            .authority_generation;

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
            authority_generation,
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
        self.acknowledge_capture(&output.captured_file_hashes)?;

        let snapshot_hex = hex::encode(&output.record.snapshot_id);
        println!(
            "{} Snapshot {} captured ({} files, {} chunks)",
            "Agent:".green().bold(),
            snapshot_hex.yellow(),
            tracked.len(),
            output.chunks.len()
        );
        let _ = self.store.record_activity(
            "WATCH_SNAPSHOT",
            &format!("Watcher captured snapshot {snapshot_hex}"),
            &serde_json::json!({
                "snapshot_id": snapshot_hex,
                "files": tracked.len(),
                "chunks": output.chunks.len(),
            })
            .to_string(),
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
                    ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS,
                )
                .await
            {
                Ok(_) => {
                    let _ = self.store.mark_upload_completed(&snap_id_arr);
                    let _ = self.store.record_activity(
                        "WATCH_SYNC_OK",
                        &format!("Watcher replicated snapshot {snapshot_hex}"),
                        &serde_json::json!({
                            "snapshot_id": snapshot_hex,
                            "operators": self.config.operators.len(),
                        })
                        .to_string(),
                    );
                    println!("Agent: Complete recovery set verified on three operators");
                }
                Err(e) => {
                    let err_msg = e.to_string();
                    let _ = self.store.record_upload_failure(&snap_id_arr, &err_msg);
                    let _ = self.store.record_activity(
                        "WATCH_SYNC_FAILED",
                        &format!("Watcher replication failed for snapshot {snapshot_hex}"),
                        &serde_json::json!({ "snapshot_id": snapshot_hex, "error": err_msg })
                            .to_string(),
                    );
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
            let outcome = async {
                let (record, _) = self.store.get_snapshot(&item.snapshot_id)?;
                if record.compute_record_cid()? != item.record_cid {
                    bail!("Pending upload does not match its snapshot record");
                }
                // Sealed epoch envelopes are randomized. Rebuilding this set
                // would change the closure already authenticated by the head.
                let recovery_set = self.store.get_recovery_set(&item.record_cid)?;
                let wire_objects = self.store.recovery_objects(&recovery_set)?;
                let head = self
                    .store
                    .get_head_for_snapshot(&item.record_cid)?
                    .context("Pending snapshot has no retained signed head")?;
                let closure_digest = recovery_set.closure.compute_base_closure_digest()?;
                if head.snapshot_id != item.record_cid
                    || head.parent_snapshot_ids != record.parent_snapshot_ids
                    || head.closure_digest != closure_digest
                {
                    bail!("Pending snapshot's retained head has inconsistent bindings");
                }
                pool.replicate_and_verify(
                    &vault_id,
                    &device_sk,
                    &wire_objects,
                    &closure_digest,
                    recovery_set.closure.total_bytes,
                    90,
                    &recovery_set.locator,
                    &to_canonical_cbor(&head)?,
                    &recovery_set.records,
                    ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS,
                )
                .await?;
                Ok::<(), anyhow::Error>(())
            }
            .await;
            match outcome {
                Ok(()) => {
                    self.store.mark_upload_completed(&item.snapshot_id)?;
                    println!(
                        "Agent: Retry succeeded for pending snapshot {}",
                        hex::encode(item.snapshot_id)
                    );
                }
                Err(error) => {
                    self.store
                        .record_upload_failure(&item.snapshot_id, &error.to_string())?;
                }
            }
        }

        Ok(())
    }

    /// Native events are coalesced into a bounded queue. A dedicated worker owns
    /// blocking hashing/capture and remote uploads, keeping shutdown and event
    /// reception responsive even while an operator is slow.
    pub async fn run_loop(
        &self,
        mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
    ) -> Result<()> {
        let (event_tx, mut event_rx) = tokio::sync::mpsc::channel::<notify::Result<Event>>(128);
        let overflow = Arc::new(AtomicBool::new(false));
        let callback_overflow = overflow.clone();
        let watcher_result = RecommendedWatcher::new(
            move |result| {
                if event_tx.try_send(result).is_err() {
                    callback_overflow.store(true, Ordering::Release);
                }
            },
            Config::default(),
        );
        let mut watcher = watcher_result.ok();
        if let Some(native) = watcher.as_mut() {
            if let Err(error) = native.watch(&self.config.root_dir, RecursiveMode::Recursive) {
                eprintln!("Native watcher unavailable ({error}); using periodic scans.");
                watcher = None;
            }
        }
        let (work_tx, mut work_rx) = tokio::sync::mpsc::channel::<String>(1);
        let config = self.config.clone();
        let hashes = self.hash_cache.clone();
        let mut worker_shutdown = shutdown_rx.resubscribe();
        let worker = std::thread::Builder::new().name("ciphervault-capture".into()).spawn(move || -> Result<()> {
            let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
            runtime.block_on(async move {
                let mut worker = VaultWatcher::new(config)?;
                worker.hash_cache = hashes;
                let mut last_retry = Instant::now();
                loop {
                    let label = tokio::select! {
                        _ = worker_shutdown.recv() => break,
                        job = work_rx.recv() => match job { Some(job) => job, None => break },
                    };
                    let operation = async {
                        if worker.check_for_changes()? {
                            if worker.config.dry_run {
                                let report = worker.inspect_pending_capture()?;
                                println!("[DRY-RUN] Would capture {} file(s), {} chunks, {} bytes", report.files, report.chunks, report.bytes);
                            } else {
                                worker.capture_and_sync(Some(format!("Auto-snapshot: {label}"))).await?;
                            }
                        }
                        if !worker.config.dry_run && last_retry.elapsed() >= Duration::from_secs(30) {
                            last_retry = Instant::now();
                            worker.retry_pending_uploads().await?;
                        }
                        Ok::<(), anyhow::Error>(())
                    };
                    tokio::select! {
                        _ = worker_shutdown.recv() => break,
                        result = tokio::time::timeout(Duration::from_secs(90), operation) => {
                            match result {
                                Ok(Ok(())) => {},
                                Ok(Err(error)) => { eprintln!("Watcher capture/sync failed: {error}");
                                    let _ = worker.store.record_activity("WATCH_CAPTURE_FAILED", "Watcher capture or sync failed; pending work will retry", &serde_json::json!({"error": error.to_string()}).to_string()); },
                                Err(_) => { eprintln!("Watcher upload timed out; durable pending upload will retry");
                                    let _ = worker.store.record_activity("WATCH_SYNC_TIMEOUT", "Watcher upload timed out; pending upload retained", "{}"); },
                            }
                        }
                    }
                }
                Ok(())
            })
        })?;
        let mut ticker = tokio::time::interval(Duration::from_millis(100));
        let mut last_change = Some((Instant::now(), "startup scan".to_string()));
        let mut last_poll = Instant::now();
        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => break,
                Some(result) = event_rx.recv() => {
                    match result {
                        Ok(event) if event.paths.iter().any(|path| !is_ignored_path(path)) => {
                            last_change = Some((Instant::now(), "filesystem change".into()));
                        },
                        Err(_) => { overflow.store(true, Ordering::Release); },
                        _ => {},
                    }
                },
                _ = ticker.tick() => {
                    if overflow.swap(false, Ordering::AcqRel) {
                        last_change = Some((Instant::now(), "coalesced filesystem changes".into()));
                    }
                    if let Some((at, label)) = &last_change {
                        if at.elapsed() >= self.config.debounce && work_tx.try_send(label.clone()).is_ok() {
                            last_change = None;
                        }
                    }
                    if last_poll.elapsed() >= Duration::from_secs(3) {
                        last_poll = Instant::now();
                        // Lost events never advance the committed baseline.
                        if last_change.is_none() { let _ = work_tx.try_send("fallback scan".into()); }
                    }
                }
            }
        }
        drop(watcher);
        drop(work_tx);
        tokio::task::spawn_blocking(move || {
            worker
                .join()
                .map_err(|_| anyhow::anyhow!("Watcher worker panicked"))?
        })
        .await??;
        Ok(())
    }
}

/// Reject links in every existing ancestor as well as the final component.
/// Repeating this after the handle read also detects path substitution while
/// hashing; the handle itself is opened without following a final-component link.
fn validate_no_links(path: &Path) -> Result<()> {
    for ancestor in path.ancestors() {
        if ancestor.as_os_str().is_empty() {
            continue;
        }
        let metadata = match fs::symlink_metadata(ancestor) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.into()),
        };
        let is_link = metadata.file_type().is_symlink();
        #[cfg(windows)]
        let is_link = {
            use std::os::windows::fs::MetadataExt;
            is_link || metadata.file_attributes() & 0x400 != 0
        };
        if is_link {
            bail!("Tracked path contains a link: {}", ancestor.display());
        }
    }
    Ok(())
}

#[cfg(test)]
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
    false
}

fn is_ignored_path(path: &Path) -> bool {
    path.components().any(|part| {
        matches!(
            part.as_os_str().to_str(),
            Some(".git" | ".ciphervault" | "target" | "node_modules")
        )
    })
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
        assert!(is_ignored_path(Path::new(
            "/workspace/.ciphervault/vault.db"
        )));
        assert!(is_ignored_path(Path::new("/workspace/target/debug/app")));
        assert!(!is_ignored_path(Path::new("/workspace/.env")));
        assert!(!is_ignored_path(Path::new("/workspace/config/key.pem")));
    }
}
