//! D6 object-store spike: faithful file-baseline model.
//!
//! Mirrors `OperatorState::persist_atomic` (tmp file + write + fsync +
//! atomic rename) and the `objects/<cid_hex>` layout. Digest validation,
//! metrics, and locking are product logic orthogonal to the engine
//! comparison, so the model omits them; all three stay in the product
//! whatever the engine. No directory fsync on Windows, matching the
//! product's `#[cfg(unix)]` gate — Linux file numbers would be slightly
//! slower (one extra fsync per object).

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use crate::ObjStore;

pub struct FileStore {
    objects: PathBuf,
    tmp_counter: AtomicU64,
}

impl FileStore {
    pub fn open(dir: &Path) -> Result<Self, String> {
        let objects = dir.join("objects");
        fs::create_dir_all(&objects).map_err(|e| e.to_string())?;
        Ok(Self {
            objects,
            tmp_counter: AtomicU64::new(0),
        })
    }
}

impl ObjStore for FileStore {
    fn put(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), String> {
        let name = crate::hex(key);
        let path = self.objects.join(&name);
        let n = self.tmp_counter.fetch_add(1, Ordering::Relaxed);
        let tmp = self
            .objects
            .join(format!("{name}.{}.{n}.tmp", std::process::id()));
        let result = (|| -> std::io::Result<()> {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&tmp)?;
            file.write_all(value)?;
            file.sync_all()?;
            drop(file);
            fs::rename(&tmp, &path)?;
            Ok(())
        })();
        if result.is_err() {
            let _ = fs::remove_file(&tmp);
        }
        result.map_err(|e| e.to_string())
    }

    fn flush(&mut self) -> Result<(), String> {
        // Every file put is already durable; batching does not exist here.
        Ok(())
    }

    fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        match fs::read(self.objects.join(crate::hex(key))) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.to_string()),
        }
    }

    fn present_indices(&self) -> Result<Vec<u64>, String> {
        let mut out = Vec::new();
        for entry in fs::read_dir(&self.objects).map_err(|e| e.to_string())? {
            let entry = entry.map_err(|e| e.to_string())?;
            let name = entry.file_name().to_string_lossy().into_owned();
            // 64-hex object files only; .tmp crash debris is ignored here
            // and counted separately via `debris_count`.
            if name.len() != 64 {
                continue;
            }
            let raw = crate::unhex(&name).map_err(|e| format!("bad object name: {e}"))?;
            let mut idx = [0u8; 8];
            idx.copy_from_slice(&raw[..8]);
            out.push(u64::from_be_bytes(idx));
        }
        out.sort_unstable();
        Ok(out)
    }

    fn debris_count(&self) -> u64 {
        fs::read_dir(&self.objects)
            .map(|entries| {
                entries
                    .filter_map(|entry| entry.ok())
                    .filter(|entry| entry.file_name().to_string_lossy().ends_with(".tmp"))
                    .count() as u64
            })
            .unwrap_or(0)
    }
}
