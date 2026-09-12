//! # CipherVault Maintenance Fleet Persistent Storage
//!
//! Provides SQLite persistence for registered vault locators, replication audit histories,
//! repair telemetry, and operator node health.

use anyhow::{Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Mutex;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackedVault {
    pub locator_hex: String,
    pub label: String,
    pub registered_at_utc: u64,
    pub last_audit_at_utc: Option<u64>,
    pub last_status: String,
    pub replica_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub id: i64,
    pub locator_hex: String,
    pub timestamp_utc: u64,
    pub healthy: bool,
    pub total_objects: usize,
    pub degraded_objects: usize,
    pub details_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperatorNodeRecord {
    pub endpoint: String,
    pub last_seen_utc: u64,
    pub latency_ms: u64,
    pub is_healthy: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetSummary {
    pub total_tracked_vaults: usize,
    pub healthy_vaults: usize,
    pub degraded_vaults: usize,
    pub total_audits_recorded: usize,
    pub online_operators: usize,
    pub total_operators: usize,
}

pub struct MaintenanceDb {
    conn: Mutex<Connection>,
}

impl MaintenanceDb {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = Connection::open(path).context(format!(
            "Failed to open maintenance SQLite database at '{}'",
            path.display()
        ))?;

        // Initialize WAL mode and busy timeout for high concurrency
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "busy_timeout", 5000)?;

        conn.execute_batch(
            r#"
            CREATE TABLE IF NOT EXISTS tracked_vaults (
                locator_hex TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                registered_at_utc INTEGER NOT NULL,
                last_audit_at_utc INTEGER,
                last_status TEXT NOT NULL,
                replica_count INTEGER NOT NULL DEFAULT 3
            );

            CREATE TABLE IF NOT EXISTS audit_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                locator_hex TEXT NOT NULL,
                timestamp_utc INTEGER NOT NULL,
                healthy INTEGER NOT NULL,
                total_objects INTEGER NOT NULL,
                degraded_objects INTEGER NOT NULL,
                details_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS operator_nodes (
                endpoint TEXT PRIMARY KEY,
                last_seen_utc INTEGER NOT NULL,
                latency_ms INTEGER NOT NULL,
                is_healthy INTEGER NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_audit_locator ON audit_history(locator_hex);
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_history(timestamp_utc);
            "#,
        )?;

        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn register_vault(&self, locator_hex: &str, label: Option<&str>) -> Result<()> {
        let clean_locator = locator_hex.trim().trim_start_matches("0x").to_lowercase();
        if clean_locator.len() != 64 || hex::decode(&clean_locator).is_err() {
            anyhow::bail!("Invalid vault locator: must be 32 bytes (64 hex characters)");
        }

        let lbl = label.unwrap_or("Production Vault");
        let now = Utc::now().timestamp() as u64;

        let lock = self.conn.lock().unwrap();
        lock.execute(
            r#"
            INSERT INTO tracked_vaults (locator_hex, label, registered_at_utc, last_status, replica_count)
            VALUES (?1, ?2, ?3, 'Registered', 3)
            ON CONFLICT(locator_hex) DO UPDATE SET label = excluded.label
            "#,
            params![clean_locator, lbl, now],
        )?;

        Ok(())
    }

    pub fn list_vaults(&self) -> Result<Vec<TrackedVault>> {
        let lock = self.conn.lock().unwrap();
        let mut stmt = lock.prepare(
            "SELECT locator_hex, label, registered_at_utc, last_audit_at_utc, last_status, replica_count FROM tracked_vaults ORDER BY registered_at_utc ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(TrackedVault {
                locator_hex: row.get(0)?,
                label: row.get(1)?,
                registered_at_utc: row.get(2)?,
                last_audit_at_utc: row.get(3)?,
                last_status: row.get(4)?,
                replica_count: row.get::<_, i64>(5)? as usize,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn record_audit(
        &self,
        locator_hex: &str,
        healthy: bool,
        total_objects: usize,
        degraded_objects: usize,
        details_json: &str,
    ) -> Result<()> {
        let clean_locator = locator_hex.trim().trim_start_matches("0x").to_lowercase();
        let now = Utc::now().timestamp() as u64;
        let status_str = if healthy { "Healthy" } else { "Degraded" };

        let lock = self.conn.lock().unwrap();
        lock.execute(
            r#"
            INSERT INTO audit_history (locator_hex, timestamp_utc, healthy, total_objects, degraded_objects, details_json)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6)
            "#,
            params![clean_locator, now, healthy as i32, total_objects as i64, degraded_objects as i64, details_json],
        )?;

        lock.execute(
            r#"
            UPDATE tracked_vaults
            SET last_audit_at_utc = ?1, last_status = ?2
            WHERE locator_hex = ?3
            "#,
            params![now, status_str, clean_locator],
        )?;

        Ok(())
    }

    pub fn update_operator_health(
        &self,
        endpoint: &str,
        latency_ms: u64,
        is_healthy: bool,
    ) -> Result<()> {
        let now = Utc::now().timestamp() as u64;
        let lock = self.conn.lock().unwrap();
        lock.execute(
            r#"
            INSERT INTO operator_nodes (endpoint, last_seen_utc, latency_ms, is_healthy)
            VALUES (?1, ?2, ?3, ?4)
            ON CONFLICT(endpoint) DO UPDATE SET
                last_seen_utc = excluded.last_seen_utc,
                latency_ms = excluded.latency_ms,
                is_healthy = excluded.is_healthy
            "#,
            params![endpoint, now, latency_ms as i64, is_healthy as i32],
        )?;

        Ok(())
    }

    pub fn get_fleet_summary(&self) -> Result<FleetSummary> {
        let lock = self.conn.lock().unwrap();

        let total_tracked: i64 =
            lock.query_row("SELECT COUNT(*) FROM tracked_vaults", [], |r| r.get(0))?;

        let healthy_vaults: i64 = lock.query_row(
            "SELECT COUNT(*) FROM tracked_vaults WHERE last_status = 'Healthy'",
            [],
            |r| r.get(0),
        )?;

        let degraded_vaults = (total_tracked - healthy_vaults).max(0);

        let total_audits: i64 =
            lock.query_row("SELECT COUNT(*) FROM audit_history", [], |r| r.get(0))?;

        let total_ops: i64 =
            lock.query_row("SELECT COUNT(*) FROM operator_nodes", [], |r| r.get(0))?;

        let online_ops: i64 = lock.query_row(
            "SELECT COUNT(*) FROM operator_nodes WHERE is_healthy = 1",
            [],
            |r| r.get(0),
        )?;

        Ok(FleetSummary {
            total_tracked_vaults: total_tracked as usize,
            healthy_vaults: healthy_vaults as usize,
            degraded_vaults: degraded_vaults as usize,
            total_audits_recorded: total_audits as usize,
            online_operators: online_ops as usize,
            total_operators: total_ops as usize,
        })
    }

    pub fn list_operator_nodes(&self) -> Result<Vec<OperatorNodeRecord>> {
        let lock = self.conn.lock().unwrap();
        let mut stmt = lock.prepare(
            "SELECT endpoint, last_seen_utc, latency_ms, is_healthy FROM operator_nodes ORDER BY endpoint ASC",
        )?;

        let rows = stmt.query_map([], |row| {
            Ok(OperatorNodeRecord {
                endpoint: row.get(0)?,
                last_seen_utc: row.get(1)?,
                latency_ms: row.get::<_, i64>(2)? as u64,
                is_healthy: row.get::<_, i32>(3)? == 1,
            })
        })?;

        let mut out = Vec::new();
        for r in rows {
            out.push(r?);
        }
        Ok(out)
    }

    pub fn get_recent_audits(&self, limit: usize) -> Result<Vec<AuditRecord>> {
        let lock = self.conn.lock().unwrap();
        let mut stmt = lock.prepare(
            "SELECT id, locator_hex, timestamp_utc, healthy, total_objects, degraded_objects, details_json FROM audit_history ORDER BY timestamp_utc DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            Ok(AuditRecord {
                id: row.get(0)?,
                locator_hex: row.get(1)?,
                timestamp_utc: row.get(2)?,
                healthy: row.get::<_, i32>(3)? == 1,
                total_objects: row.get::<_, i64>(4)? as usize,
                degraded_objects: row.get::<_, i64>(5)? as usize,
                details_json: row.get(6)?,
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

    #[test]
    fn test_maintenance_db_persistence_and_summary() {
        let test_dir = std::env::temp_dir().join(format!(
            "cv_maint_db_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&test_dir).unwrap();
        let db_path = test_dir.join("maintenance.db");

        let db = MaintenanceDb::open(&db_path).unwrap();

        let locator = "a".repeat(64);
        db.register_vault(&locator, Some("Vault Alpha")).unwrap();

        let vaults = db.list_vaults().unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].label, "Vault Alpha");
        assert_eq!(vaults[0].last_status, "Registered");

        // Record audit
        db.record_audit(&locator, true, 10, 0, "{}").unwrap();
        let vaults_after = db.list_vaults().unwrap();
        assert_eq!(vaults_after[0].last_status, "Healthy");
        assert!(vaults_after[0].last_audit_at_utc.is_some());

        // Operator nodes
        db.update_operator_health("http://127.0.0.1:8787", 45, true)
            .unwrap();
        db.update_operator_health("http://127.0.0.1:8788", 120, true)
            .unwrap();
        db.update_operator_health("http://127.0.0.1:8789", 0, false)
            .unwrap();

        let summary = db.get_fleet_summary().unwrap();
        assert_eq!(summary.total_tracked_vaults, 1);
        assert_eq!(summary.healthy_vaults, 1);
        assert_eq!(summary.degraded_vaults, 0);
        assert_eq!(summary.total_audits_recorded, 1);
        assert_eq!(summary.total_operators, 3);
        assert_eq!(summary.online_operators, 2);

        let _ = std::fs::remove_dir_all(test_dir);
    }
}
