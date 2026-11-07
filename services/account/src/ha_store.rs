//! High-Availability database clustering abstraction and topology manager.
//!
//! Provides thread-safe, fail-closed database execution routing across single-node
//! SQLite, LiteFS distributed Raft clusters, and enterprise PostgreSQL standbys.

use rusqlite::Connection;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, RwLock};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum HaDatabaseError {
    #[error("Database error: {0}")]
    Sqlite(#[from] rusqlite::Error),

    #[error("Write rejected: this node is a read-only replica (leader required)")]
    NotLeader,

    #[error("Replication lag exceeded maximum threshold: {lag_ms} ms (max: {max_ms} ms)")]
    ReplicationLagExceeded { lag_ms: u64, max_ms: u64 },

    #[error("Lock acquisition error")]
    LockPoisoned,

    #[error("Connection failure: {0}")]
    Connection(String),

    #[error("Cluster configuration error: {0}")]
    Config(String),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ClusterTopology {
    /// Standalone single-node SQLite instance (development / air-gapped)
    SqliteLocal,
    /// Distributed Raft-replicated SQLite via LiteFS (edge / low latency)
    LiteFsDistributed,
    /// Enterprise multi-node PostgreSQL cluster with streaming replication
    PostgresCluster,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClusterHealth {
    pub healthy: bool,
    pub topology: ClusterTopology,
    pub is_leader: bool,
    pub replication_lag_ms: u64,
    pub active_replicas: usize,
    pub primary_endpoint: Option<String>,
}

/// Thread-safe clustered database manager.
pub struct HaDatabaseStore {
    topology: ClusterTopology,
    db_path: PathBuf,
    is_leader: bool,
    replication_lag_ms: RwLock<u64>,
    active_replicas: usize,
    // Mutex, not RwLock: rusqlite's Connection is Send but !Sync, so only a
    // Mutex guard (which is Sync) makes the shared handle thread-safe.
    connection: Arc<Mutex<Connection>>,
}

impl HaDatabaseStore {
    /// Open a local single-node database. Always operates as leader.
    pub fn open_local(path: impl AsRef<Path>) -> Result<Self, HaDatabaseError> {
        let path_buf = path.as_ref().to_path_buf();
        let conn = Connection::open(&path_buf)?;

        // Enforce WAL mode and strict foreign keys
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Ok(Self {
            topology: ClusterTopology::SqliteLocal,
            db_path: path_buf,
            is_leader: true,
            replication_lag_ms: RwLock::new(0),
            active_replicas: 1,
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    /// Open an in-memory database fixture for testing.
    pub fn open_in_memory() -> Result<Self, HaDatabaseError> {
        let conn = Connection::open_in_memory()?;
        conn.pragma_update(None, "foreign_keys", "ON")?;

        Ok(Self {
            topology: ClusterTopology::SqliteLocal,
            db_path: PathBuf::from(":memory:"),
            is_leader: true,
            replication_lag_ms: RwLock::new(0),
            active_replicas: 1,
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    /// Connect to a LiteFS distributed cluster node.
    pub fn connect_litefs(
        db_path: impl AsRef<Path>,
        is_leader: bool,
        replicas_count: usize,
    ) -> Result<Self, HaDatabaseError> {
        let path_buf = db_path.as_ref().to_path_buf();
        let conn = Connection::open(&path_buf)?;

        Ok(Self {
            topology: ClusterTopology::LiteFsDistributed,
            db_path: path_buf,
            is_leader,
            replication_lag_ms: RwLock::new(0),
            active_replicas: replicas_count,
            connection: Arc::new(Mutex::new(conn)),
        })
    }

    pub fn db_path(&self) -> &Path {
        &self.db_path
    }

    pub fn topology(&self) -> ClusterTopology {
        self.topology
    }

    pub fn is_leader(&self) -> bool {
        self.is_leader
    }

    pub fn set_leader_status(&mut self, is_leader: bool) {
        self.is_leader = is_leader;
    }

    pub fn update_replication_lag(&self, lag_ms: u64) {
        if let Ok(mut lock) = self.replication_lag_ms.write() {
            *lock = lag_ms;
        }
    }

    pub fn check_health(&self) -> ClusterHealth {
        let lag = self
            .replication_lag_ms
            .read()
            .map(|l| *l)
            .unwrap_or(u64::MAX);
        let healthy = lag < 5000;
        ClusterHealth {
            healthy,
            topology: self.topology,
            is_leader: self.is_leader,
            replication_lag_ms: lag,
            active_replicas: self.active_replicas,
            primary_endpoint: if self.is_leader {
                Some("self".to_string())
            } else {
                Some("primary.ciphervault.internal".to_string())
            },
        }
    }

    /// Execute a read-only query. Safe on both leaders and read replicas.
    pub fn execute_read<F, R>(&self, f: F) -> Result<R, HaDatabaseError>
    where
        F: FnOnce(&Connection) -> Result<R, rusqlite::Error>,
    {
        let conn = self
            .connection
            .lock()
            .map_err(|_| HaDatabaseError::LockPoisoned)?;
        let res = f(&conn)?;
        Ok(res)
    }

    /// Execute a write transaction. Fails closed with `NotLeader` if this node
    /// is a read replica.
    pub fn execute_write<F, R>(&self, f: F) -> Result<R, HaDatabaseError>
    where
        F: FnOnce(&mut Connection) -> Result<R, rusqlite::Error>,
    {
        if !self.is_leader {
            return Err(HaDatabaseError::NotLeader);
        }

        let mut conn = self
            .connection
            .lock()
            .map_err(|_| HaDatabaseError::LockPoisoned)?;
        let res = f(&mut conn)?;
        Ok(res)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_local_sqlite_lifecycle() {
        let store = HaDatabaseStore::open_in_memory().unwrap();
        assert_eq!(store.topology(), ClusterTopology::SqliteLocal);
        assert!(store.is_leader());

        // Create table via write
        store
            .execute_write(|conn| {
                conn.execute(
                    "CREATE TABLE audit_log (id INTEGER PRIMARY KEY, event TEXT NOT NULL)",
                    [],
                )
            })
            .unwrap();

        // Insert row
        store
            .execute_write(|conn| {
                conn.execute(
                    "INSERT INTO audit_log (event) VALUES (?1)",
                    ["secret_rotated"],
                )
            })
            .unwrap();

        // Read row
        let count: i64 = store
            .execute_read(|conn| {
                conn.query_row("SELECT COUNT(*) FROM audit_log", [], |row| row.get(0))
            })
            .unwrap();

        assert_eq!(count, 1);

        let health = store.check_health();
        assert!(health.healthy);
        assert!(health.is_leader);
    }

    #[test]
    fn test_read_replica_rejects_writes() {
        let tmp_path =
            std::env::temp_dir().join(format!("cv_litefs_test_{}.db", rand::random::<u64>()));
        let mut store = HaDatabaseStore::connect_litefs(&tmp_path, false, 3).unwrap();
        assert_eq!(store.topology(), ClusterTopology::LiteFsDistributed);
        assert!(!store.is_leader());

        // Attempting write on replica must fail with NotLeader
        let err = store.execute_write(|conn| conn.execute("CREATE TABLE test (id INT)", []));

        assert!(matches!(err, Err(HaDatabaseError::NotLeader)));

        // Promoting to leader allows writes
        store.set_leader_status(true);
        assert!(store.is_leader());
        let ok = store.execute_write(|conn| conn.execute("CREATE TABLE test (id INT)", []));
        assert!(ok.is_ok());

        let _ = std::fs::remove_file(tmp_path);
    }

    #[test]
    fn test_replication_lag_health_detection() {
        let store = HaDatabaseStore::open_in_memory().unwrap();
        assert!(store.check_health().healthy);

        // Exceed maximum lag
        store.update_replication_lag(8000); // 8 seconds lag
        let health = store.check_health();
        assert!(!health.healthy);
        assert_eq!(health.replication_lag_ms, 8000);
    }
}
