//! D6 object-store spike: redb adapter (pure-Rust ACID embedded KV).

use std::path::Path;

use redb::{ReadableDatabase, ReadableTable, TableDefinition};

use crate::ObjStore;

pub struct RedbStore {
    db: redb::Database,
    batch: usize,
    pending: Vec<([u8; 32], Vec<u8>)>,
}

fn table() -> TableDefinition<'static, &'static [u8], &'static [u8]> {
    TableDefinition::new("objects")
}

impl RedbStore {
    pub fn open(dir: &Path, batch: usize) -> Result<Self, String> {
        std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        let db = redb::Database::create(dir.join("objects.redb")).map_err(|e| e.to_string())?;
        Ok(Self {
            db,
            batch: batch.max(1),
            pending: Vec::new(),
        })
    }
}

impl ObjStore for RedbStore {
    fn put(&mut self, key: &[u8; 32], value: &[u8]) -> Result<(), String> {
        self.pending.push((*key, value.to_vec()));
        if self.pending.len() >= self.batch {
            self.flush()?;
        }
        Ok(())
    }

    fn flush(&mut self) -> Result<(), String> {
        if self.pending.is_empty() {
            return Ok(());
        }
        // redb commits are durable (fsync) by default: batch=1 measures the
        // naive per-object port, batch=1000 the grouped-commit shape.
        let txn = self.db.begin_write().map_err(|e| e.to_string())?;
        {
            let mut tbl = txn.open_table(table()).map_err(|e| e.to_string())?;
            for (key, value) in &self.pending {
                tbl.insert(key.as_slice(), value.as_slice())
                    .map_err(|e| e.to_string())?;
            }
        }
        txn.commit().map_err(|e| e.to_string())?;
        self.pending.clear();
        Ok(())
    }

    fn get(&self, key: &[u8; 32]) -> Result<Option<Vec<u8>>, String> {
        let txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let tbl = txn.open_table(table()).map_err(|e| e.to_string())?;
        Ok(tbl
            .get(key.as_slice())
            .map_err(|e| e.to_string())?
            .map(|guard| guard.value().to_vec()))
    }

    fn present_indices(&self) -> Result<Vec<u64>, String> {
        let txn = self.db.begin_read().map_err(|e| e.to_string())?;
        let tbl = txn.open_table(table()).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for item in tbl.iter().map_err(|e| e.to_string())? {
            let (key, _) = item.map_err(|e| e.to_string())?;
            let raw: &[u8] = key.value();
            let mut idx = [0u8; 8];
            idx.copy_from_slice(&raw[..8]);
            out.push(u64::from_be_bytes(idx));
        }
        Ok(out)
    }
}
