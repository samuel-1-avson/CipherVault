//! Persisted, independently pinned inventories for unattended verification.
use anyhow::{ensure, Context, Result};
use ciphervault_format::{from_canonical_cbor, HeadRecord, RecoverySet};
use ciphervault_storage::{LeaseReceipt, OperatorClient};
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

use crate::{engine::RecoveryAudit, MaintenanceDb, MaintenanceEngine};

/// Public recovery metadata; root and operator keys must be supplied from an
/// independently trusted local export, never learned from a recovery response.
#[derive(Clone, Serialize, Deserialize)]
pub struct MaintenanceInventory {
    pub set: RecoverySet,
    pub head: Vec<u8>,
    pub vault_id: [u8; 32],
    pub recovery_signing_pk: [u8; 32],
    pub operator_keys: HashMap<String, [u8; 32]>,
    pub required_replicas: usize,
    #[serde(default)]
    pub leases: Vec<LeaseReceipt>,
    #[serde(default)]
    pub account_id: Option<String>,
    #[serde(default)]
    pub device_id_hex: Option<String>,
}

impl MaintenanceInventory {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.required_replicas > 0 && self.required_replicas <= 32,
            "Invalid replica target"
        );
        ensure!(
            self.operator_keys.len() <= 32,
            "Too many operators in inventory"
        );
        ensure!(
            self.account_id.is_some() == self.device_id_hex.is_some(),
            "Incomplete account/device binding"
        );
        let mut records = self.set.records.clone();
        records.push(self.head.clone());
        let (head, _) = ciphervault_recovery::trust::select_head(
            &records,
            &self.vault_id,
            &self.recovery_signing_pk,
        )?;
        let supplied: HeadRecord = from_canonical_cbor(&self.head)?;
        ensure!(
            head == supplied,
            "Inventory head is not the authenticated maximal head"
        );
        ensure!(
            head.closure_digest == self.set.closure.compute_base_closure_digest()?.to_vec()
                && head.snapshot_id == self.set.closure.snapshot_record_cid,
            "Inventory does not match signed head"
        );
        ensure!(
            self.set.closure.snapshot_id.len() == 32
                && self.set.closure.manifest_cid.len() == 32
                && self.set.closure.chunk_cids.len() <= 10_000
                && self
                    .set
                    .closure
                    .chunk_cids
                    .iter()
                    .chain(&self.set.closure.envelope_ids)
                    .all(|cid| cid.len() == 32),
            "Invalid closure object identifiers"
        );
        Ok(())
    }

    pub fn engine(&self) -> MaintenanceEngine {
        MaintenanceEngine::from_clients(
            self.operator_keys
                .iter()
                .map(|(endpoint, key)| {
                    let client = OperatorClient::new_pinned(endpoint.clone(), *key);
                    if let (Some(account), Some(device)) = (&self.account_id, &self.device_id_hex) {
                        client.with_account_identity(account, device);
                    }
                    client
                })
                .collect(),
        )
    }
}

/// One persisted job attempt. Missing write credentials retain observable
/// deficits; read-only verification still runs using anonymous ciphertext reads.
pub async fn run_inventory_job(
    db: &MaintenanceDb,
    inventory: &mut MaintenanceInventory,
    signing_key: Option<&SigningKey>,
) -> Result<RecoveryAudit> {
    inventory.validate()?;
    let engine = inventory.engine();
    let mut sessions = if let Some(key) = signing_key {
        engine.authenticate_all(&inventory.vault_id, key).await
    } else {
        HashMap::new()
    };
    let write_sessions = sessions.clone();
    for endpoint in engine.endpoints() {
        sessions
            .entry(endpoint.clone())
            .or_insert_with(|| "recovery_anonymous".into());
    }
    let mut report = engine
        .audit_recovery_set(&inventory.set, &inventory.head, &sessions)
        .await?;
    let locator = hex::encode(inventory.set.locator);
    if let Some(key) = signing_key {
        if (!report.objects.degraded_objects.is_empty() || !report.discovery_missing.is_empty())
            && !write_sessions.is_empty()
        {
            let result = engine
                .repair_closure(&report.objects, &write_sessions, key)
                .await?;
            db.record_repair(
                &locator,
                result.objects_repaired,
                result.objects_failed,
                result.elapsed_secs,
            )?;
            // Discovery is part of the recovery promise too. Restore missing
            // certified metadata/head after authenticated object repair.
            for (endpoint, operator_pk) in &inventory.operator_keys {
                if report.discovery_missing.contains(endpoint)
                    && write_sessions.contains_key(endpoint)
                {
                    let client = OperatorClient::new_pinned(endpoint.clone(), *operator_pk);
                    if let (Some(account), Some(device)) =
                        (&inventory.account_id, &inventory.device_id_hex)
                    {
                        client.with_account_identity(account, device);
                    }
                    // Authentication carries scope into this client instance.
                    if let Ok(token) = client.authenticate(&inventory.vault_id, key).await {
                        let existing = client
                            .get_recovery_records(&inventory.set.locator)
                            .await
                            .unwrap_or_default();
                        for record in inventory
                            .set
                            .records
                            .iter()
                            .chain(std::iter::once(&inventory.head))
                        {
                            if !existing.contains(record) {
                                let _ = client
                                    .append_recovery_record(
                                        &token,
                                        &inventory.set.locator,
                                        record.clone(),
                                    )
                                    .await;
                            }
                        }
                    }
                }
            }
            report = engine
                .audit_recovery_set(&inventory.set, &inventory.head, &sessions)
                .await?;
        }
        let now = chrono::Utc::now().timestamp().max(0) as u64;
        let due: Vec<_> = inventory
            .leases
            .iter()
            .filter(|lease| lease.expires_at_utc < now.saturating_add(14 * 86400))
            .cloned()
            .collect();
        if !due.is_empty() {
            for renewed in engine.renew_leases(&due, &write_sessions, 30).await {
                if let Some(previous) = inventory.leases.iter_mut().find(|lease| {
                    lease.lease_id == renewed.lease_id && lease.operator_id == renewed.operator_id
                }) {
                    *previous = renewed;
                }
            }
            // Verified promises survive restart; rejected renewals keep the old receipt.
            db.store_inventory(inventory)?;
        }
    }
    let distinct: HashSet<_> = report
        .recoverable_operators
        .iter()
        .filter_map(|endpoint| inventory.operator_keys.get(endpoint))
        .collect();
    report.required_replicas = inventory.required_replicas;
    report.healthy =
        distinct.len() >= inventory.required_replicas && report.objects.lost_count == 0;
    db.record_audit(
        &locator,
        report.healthy,
        report.objects.total_objects,
        report.objects.degraded_count + report.objects.lost_count,
        &serde_json::to_string(&report)?,
    )?;
    Ok(report)
}

pub fn read_inventory(path: &std::path::Path) -> Result<MaintenanceInventory> {
    ensure!(
        std::fs::metadata(path)?.len() <= 16 * 1024 * 1024,
        "Inventory exceeds 16 MiB limit"
    );
    let inventory: MaintenanceInventory = serde_json::from_slice(&std::fs::read(path)?)
        .context("Invalid maintenance inventory JSON")?;
    inventory.validate()?;
    Ok(inventory)
}
