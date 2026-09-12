use anyhow::Result;
use chrono::Utc;
use colored::*;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::{
    compute_digest, PlacementUpdate, RecoveryClosure, PROTOCOL_VERSION,
};
use ciphervault_storage::{LeaseReceipt, OperatorClient};

/// Detailed replica presence for an individual ciphertext object.
#[derive(Debug, Clone)]
pub struct ObjectReplicaStatus {
    pub cid: [u8; 32],
    pub present_on: Vec<String>,
    pub missing_on: Vec<String>,
}

/// Comprehensive audit report for a vault recovery closure across all operators.
#[derive(Debug, Clone)]
pub struct AuditReport {
    pub closure_digest: [u8; 32],
    pub total_objects: usize,
    pub healthy_count: usize,
    pub degraded_count: usize,
    pub lost_count: usize,
    pub operator_counts: HashMap<String, usize>,
    pub degraded_objects: Vec<ObjectReplicaStatus>,
}

/// Outcome of a self-repair sweep.
#[derive(Debug, Clone)]
pub struct RepairResult {
    pub objects_repaired: usize,
    pub objects_failed: usize,
    pub placement_updates: Vec<PlacementUpdate>,
}

/// Engine executing zero-knowledge replication audits, object self-repair, and lease extensions.
pub struct MaintenanceEngine {
    endpoints: Vec<String>,
    clients: Vec<OperatorClient>,
}

impl MaintenanceEngine {
    pub fn new(endpoints: Vec<String>) -> Self {
        let clients = endpoints
            .iter()
            .map(|e| OperatorClient::new(e.clone()))
            .collect();
        Self {
            endpoints,
            clients,
        }
    }

    pub fn endpoints(&self) -> &[String] {
        &self.endpoints
    }

    /// Authenticates with all operators using provided credentials.
    pub async fn authenticate_all(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
    ) -> HashMap<String, String> {
        let mut tokens = HashMap::new();
        for client in &self.clients {
            if let Ok(token) = client.authenticate(vault_id, signing_key).await {
                tokens.insert(client.endpoint().to_string(), token);
            }
        }
        tokens
    }

    /// Audits all objects required by a recovery closure across all configured operators.
    pub async fn audit_closure(
        &self,
        closure: &RecoveryClosure,
        sessions: &HashMap<String, String>,
    ) -> Result<AuditReport> {
        let closure_digest = closure.compute_base_closure_digest()?;

        // Collect all distinct CIDs in the closure
        let mut all_cids: Vec<[u8; 32]> = Vec::new();

        let mut snap_arr = [0u8; 32];
        if closure.snapshot_record_cid.len() == 32 {
            snap_arr.copy_from_slice(&closure.snapshot_record_cid);
            all_cids.push(snap_arr);
        }

        let mut manifest_arr = [0u8; 32];
        if closure.manifest_cid.len() == 32 {
            manifest_arr.copy_from_slice(&closure.manifest_cid);
            all_cids.push(manifest_arr);
        }

        for env_bytes in &closure.envelope_ids {
            if env_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(env_bytes);
                all_cids.push(arr);
            }
        }

        for chunk_bytes in &closure.chunk_cids {
            if chunk_bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(chunk_bytes);
                all_cids.push(arr);
            }
        }

        let total_objects = all_cids.len();
        let mut operator_counts: HashMap<String, usize> = HashMap::new();
        for ep in &self.endpoints {
            operator_counts.insert(ep.clone(), 0);
        }

        let mut degraded_objects = Vec::new();
        let mut healthy_count = 0;
        let mut degraded_count = 0;
        let mut lost_count = 0;

        for cid in all_cids {
            let mut present_on = Vec::new();
            let mut missing_on = Vec::new();

            for client in &self.clients {
                let ep = client.endpoint();
                if let Some(token) = sessions.get(ep) {
                    match client.get_object(token, &cid).await {
                        Ok(bytes) => {
                            if compute_digest(&bytes) == cid {
                                present_on.push(ep.to_string());
                                *operator_counts.entry(ep.to_string()).or_default() += 1;
                            } else {
                                missing_on.push(ep.to_string());
                            }
                        }
                        Err(_) => {
                            missing_on.push(ep.to_string());
                        }
                    }
                } else {
                    missing_on.push(ep.to_string());
                }
            }

            if present_on.len() == self.clients.len() {
                healthy_count += 1;
            } else if !present_on.is_empty() {
                degraded_count += 1;
                degraded_objects.push(ObjectReplicaStatus {
                    cid,
                    present_on,
                    missing_on,
                });
            } else {
                lost_count += 1;
                degraded_objects.push(ObjectReplicaStatus {
                    cid,
                    present_on,
                    missing_on,
                });
            }
        }

        Ok(AuditReport {
            closure_digest,
            total_objects,
            healthy_count,
            degraded_count,
            lost_count,
            operator_counts,
            degraded_objects,
        })
    }

    /// Automatically repairs degraded objects by fetching from intact operators,
    /// verifying digest, and uploading to missing operators with readback verification.
    pub async fn repair_closure(
        &self,
        audit: &AuditReport,
        sessions: &HashMap<String, String>,
        signing_key: &SigningKey,
    ) -> Result<RepairResult> {
        let mut objects_repaired = 0;
        let mut objects_failed = 0;
        let mut placement_updates = Vec::new();

        let client_map: HashMap<String, OperatorClient> = self
            .clients
            .iter()
            .map(|c| (c.endpoint().to_string(), c.clone()))
            .collect();

        for item in &audit.degraded_objects {
            if item.present_on.is_empty() {
                eprintln!(
                    "{} Object {} has 0 surviving replicas! Irrecoverable without offline kit.",
                    "FATAL:".red().bold(),
                    hex::encode(item.cid)
                );
                objects_failed += 1;
                continue;
            }

            // Pick first intact operator
            let source_ep = &item.present_on[0];
            let source_token = match sessions.get(source_ep) {
                Some(t) => t,
                None => {
                    objects_failed += 1;
                    continue;
                }
            };
            let source_client = &client_map[source_ep];

            // Fetch ciphertext bytes from intact operator
            let bytes = match source_client.get_object(source_token, &item.cid).await {
                Ok(b) => b,
                Err(e) => {
                    eprintln!("Failed to fetch {} from {}: {}", hex::encode(item.cid), source_ep, e);
                    objects_failed += 1;
                    continue;
                }
            };

            // Mandatory SHA-256 integrity verification
            let digest = compute_digest(&bytes);
            if digest != item.cid {
                eprintln!("Integrity mismatch on fetched object {}. Aborting repair for this object.", hex::encode(item.cid));
                objects_failed += 1;
                continue;
            }

            // Replicate to all missing operators
            let mut repaired_all = true;
            for target_ep in &item.missing_on {
                let target_token = match sessions.get(target_ep) {
                    Some(t) => t,
                    None => {
                        repaired_all = false;
                        continue;
                    }
                };
                let target_client = match client_map.get(target_ep) {
                    Some(c) => c,
                    None => {
                        repaired_all = false;
                        continue;
                    }
                };

                // Upload verified ciphertext to target operator
                if let Err(e) = target_client.put_object(target_token, &item.cid, bytes.clone()).await {
                    eprintln!("Failed to upload {} to {}: {}", hex::encode(item.cid), target_ep, e);
                    repaired_all = false;
                    continue;
                }

                // Verify readback
                match target_client.get_object(target_token, &item.cid).await {
                    Ok(readback) if compute_digest(&readback) == item.cid => {
                        // Issue signed PlacementUpdate
                        let now = Utc::now().timestamp() as u64;
                        let msg = format!("{}:{}:{}:{}", hex::encode(audit.closure_digest), hex::encode(item.cid), target_ep, now);
                        let sig = sign_with_domain(signing_key, b"placement_update", msg.as_bytes());

                        let update = PlacementUpdate {
                            version: PROTOCOL_VERSION,
                            closure_digest: audit.closure_digest.to_vec(),
                            object_cid: item.cid.to_vec(),
                            source_operator: source_ep.clone(),
                            target_operator: target_ep.clone(),
                            updated_at_utc: now,
                            verified_readback: true,
                            signature: sig.to_vec(),
                        };
                        placement_updates.push(update);
                    }
                    _ => {
                        repaired_all = false;
                    }
                }
            }

            if repaired_all {
                objects_repaired += 1;
            } else {
                objects_failed += 1;
            }
        }

        Ok(RepairResult {
            objects_repaired,
            objects_failed,
            placement_updates,
        })
    }

    /// Renews lease receipts across operators, ensuring retention runway.
    pub async fn renew_leases(
        &self,
        receipts: &[LeaseReceipt],
        sessions: &HashMap<String, String>,
        additional_days: u32,
    ) -> Vec<LeaseReceipt> {
        let mut renewed = Vec::new();
        let mut op_map = HashMap::new();
        for client in &self.clients {
            if let Ok(info) = client.get_info().await {
                if let Some(token) = sessions.get(client.endpoint()) {
                    op_map.insert(info.operator_id, (client.clone(), token.clone()));
                }
            }
        }

        for r in receipts {
            if let Some((client, token)) = op_map.get(&r.operator_id) {
                if let Ok(new_receipt) = client.renew_lease(token, &r.lease_id, additional_days, r.bytes).await {
                    renewed.push(new_receipt);
                }
            }
        }
        renewed
    }
}
