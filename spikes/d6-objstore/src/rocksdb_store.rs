//! D6 object-store spike: RocksDB adapter (native LSM embedded KV).
//!
//! NOTE: this module is written against the `rocksdb` 0.25.0 sources but
//! has NOT been compiled: the spike host has no C++ toolchain, so
//! `librocksdb-sys` cannot build there. A Linux/macOS host with a C++
//! compiler fills the RocksDB column via:
//! `cargo run --release --features rocksdb -- run --backend rocksdb ...`

use std::path::Path;

use rocksdb::{IteratorMode, Options, WriteBatch, WriteOptions, DB};

use crate::ObjStore;

pub struct RocksStore {
    db: DB,
    batch: usize,
    pending: WriteBatch,
    pending_count: usize,
    sync: bool,
}

impl RocksStore {
    pub fn open(dir: &Path, batch: usize, sync: bool) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let mut opts = Options::default();
        opts.create_if_missing(true);
        let db = DB::open(&opts, dir.join("objects.rocks")).map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            batch: batch.max(1),
            pending: WriteBatch::new(),
            pending_count: 0,
            sync,
        })
    }
}

impl ObjStore for RocksStore {
    fn put(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), String> {
        // WriteBatch::put returns () in 0.25 (errors surface at write time).
        self.pending.put(key.as_slice(), value);
        self.pending_count += 1;
        if self.pending_count >= self.batch {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        if self.pending_count == 0 {
            return Ok(());
        }
        let mut writeopts = WriteOptions::default();
        writeopts.set_sync(self.sync);
        let batch = std::mem::replace(&mut self.pending, WriteBatch::new());
        self.db
            .write_opt(batch, &writeopts)
            .map_err(|e| e.to_string())?;
        self.pending_count = 0;
        Ok(())
    }

    fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        self.db.get(key.as_slice()).map_err(|e| e.to_string())
    }

    fn present_indices(&self) -> Result<Vec<u64>, String> {
        let mut out = Vec::new();
        for item in self.db.iterator(IteratorMode::Start) {
            let (key, _) = item.map_err(|e| e.to_string())?;
            let mut idx = [0u8; 8];
            idx.copy_from_slice(&key[..8]);
            out.push(u64::from_be_bytes(idx));
        }
        Ok(out)
    }
}
