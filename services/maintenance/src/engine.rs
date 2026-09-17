use anyhow::Result;
use chrono::Utc;
use colored::*;
use ed25519_dalek::SigningKey;
use std::collections::HashMap;
use tokio::task::JoinSet;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::{compute_digest, PlacementUpdate, RecoveryClosure, PROTOCOL_VERSION};
use ciphervault_storage::{LeaseReceipt, OperatorClient};

/// Detailed replica presence for an individual ciphertext object.
#[derive(Debug, Clone, serde::Serialize)]
pub struct ObjectReplicaStatus {
    pub cid: [u8; 32],
    pub present_on: Vec<String>,
    pub missing_on: Vec<String>,
}

/// Comprehensive audit report for a vault recovery closure across all operators.
#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditReport {
    pub closure_digest: [u8; 32],
    pub total_objects: usize,
    pub healthy_count: usize,
    pub degraded_count: usize,
    pub lost_count: usize,
    pub operator_counts: HashMap<String, usize>,
    pub degraded_objects: Vec<ObjectReplicaStatus>,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct RecoveryAudit {
    pub objects: AuditReport,
    pub recoverable_operators: Vec<String>,
    pub discovery_missing: Vec<String>,
    pub required_replicas: usize,
    pub healthy: bool,
    pub checked_at_utc: i64,
}

/// Outcome of a self-repair sweep.
#[derive(Debug, Clone)]
pub struct RepairResult {
    pub objects_repaired: usize,
    pub objects_failed: usize,
    pub placement_updates: Vec<PlacementUpdate>,
    /// Detection-to-completion wall time of the sweep (repair-lag signal).
    pub elapsed_secs: u64,
}

/// Engine executing zero-knowledge replication audits, object self-repair, and lease extensions.
pub struct MaintenanceEngine {
    endpoints: Vec<String>,
    clients: Vec<OperatorClient>,
}

impl MaintenanceEngine {
    /// Verify both ciphertext objects and the exact public discovery records on each operator,
    /// optionally leveraging local object bytes for bandwidth-optimized Proof-of-Storage challenges.
    pub async fn audit_recovery_set_with_cache(
        &self,
        set: &ciphervault_format::RecoverySet,
        head: &[u8],
        sessions: &HashMap<String, String>,
        local_objects: Option<&HashMap<[u8; 32], Vec<u8>>>,
    ) -> Result<RecoveryAudit> {
        let objects = self
            .audit_closure_with_cache(&set.closure, sessions, local_objects)
            .await?;
        let mut recoverable_operators = Vec::new();
        let mut discovery_missing = Vec::new();
        let mut verified_keys = std::collections::HashSet::new();
        let mut tasks = JoinSet::new();
        for client in &self.clients {
            let client = client.clone();
            let locator = set.locator;
            let head = head.to_vec();
            let expected = set.records.clone();
            tasks.spawn(async move {
                let endpoint = client.endpoint().to_string();
                let discovery_ok = match client.get_recovery_records(&locator).await {
                    Ok(discovered) => {
                        discovered.iter().any(|r| r == &head)
                            && expected.iter().all(|r| discovered.contains(r))
                    }
                    Err(_) => false,
                };
                let pk = if discovery_ok {
                    client.get_info().await.ok().and_then(|info| {
                        hex::decode(info.operator_signing_pk_hex)
                            .ok()
                            .filter(|key| key.len() == 32)
                    })
                } else {
                    None
                };
                (endpoint, discovery_ok, pk)
            });
        }
        let mut outcomes: HashMap<String, (bool, Option<Vec<u8>>)> = HashMap::new();
        while let Some(joined) = tasks.join_next().await {
            if let Ok((endpoint, discovery_ok, pk)) = joined {
                outcomes.insert(endpoint, (discovery_ok, pk));
            }
        }
        for endpoint in &self.endpoints {
            let (discovery_ok, pk) = outcomes.remove(endpoint).unwrap_or((false, None));
            if !discovery_ok {
                discovery_missing.push(endpoint.clone());
            }
            if discovery_ok && objects.operator_counts.get(endpoint) == Some(&objects.total_objects)
            {
                if let Some(key) = pk {
                    if verified_keys.insert(key) {
                        recoverable_operators.push(endpoint.clone());
                    }
                }
            }
        }
        recoverable_operators.sort();
        recoverable_operators.dedup();
        let healthy = recoverable_operators.len() >= 3 && objects.lost_count == 0;
        Ok(RecoveryAudit {
            objects,
            recoverable_operators,
            discovery_missing,
            required_replicas: 3,
            healthy,
            checked_at_utc: Utc::now().timestamp(),
        })
    }

    /// Backward-compatible audit without local object cache.
    pub async fn audit_recovery_set(
        &self,
        set: &ciphervault_format::RecoverySet,
        head: &[u8],
        sessions: &HashMap<String, String>,
    ) -> Result<RecoveryAudit> {
        self.audit_recovery_set_with_cache(set, head, sessions, None)
            .await
    }

    /// Backward-compatible closure audit without local object cache.
    pub async fn audit_closure(
        &self,
        closure: &RecoveryClosure,
        sessions: &HashMap<String, String>,
    ) -> Result<AuditReport> {
        self.audit_closure_with_cache(closure, sessions, None).await
    }

    pub fn new(endpoints: Vec<String>) -> Self {
        let clients = endpoints
            .iter()
            .map(|e| OperatorClient::new(e.clone()))
            .collect();
        Self { endpoints, clients }
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
        let mut tasks = JoinSet::new();
        for client in &self.clients {
            let client = client.clone();
            let vault_id = *vault_id;
            let signing_key = signing_key.clone();
            tasks.spawn(async move {
                let endpoint = client.endpoint().to_string();
                match client.authenticate(&vault_id, &signing_key).await {
                    Ok(token) => Some((endpoint, token)),
                    Err(_) => None,
                }
            });
        }
        let mut tokens = HashMap::new();
        while let Some(joined) = tasks.join_next().await {
            if let Ok(Some((endpoint, token))) = joined {
                tokens.insert(endpoint, token);
            }
        }
        tokens
    }

    /// Audits all objects required by a recovery closure, optionally using known local object bytes
    /// to perform lightweight Proof-of-Storage challenges (reducing audit bandwidth by 99.99%).
    pub async fn audit_closure_with_cache(
        &self,
        closure: &RecoveryClosure,
        sessions: &HashMap<String, String>,
        local_objects: Option<&HashMap<[u8; 32], Vec<u8>>>,
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

        all_cids.sort();
        all_cids.dedup();
        anyhow::ensure!(!all_cids.is_empty(), "Empty recovery inventory");
        let total_objects = all_cids.len();
        let mut operator_counts: HashMap<String, usize> = HashMap::new();
        for ep in &self.endpoints {
            operator_counts.insert(ep.clone(), 0);
        }

        let mut degraded_objects = Vec::new();
        let mut healthy_count = 0;
        let mut degraded_count = 0;
        let mut lost_count = 0;

        let mut pk_tasks = JoinSet::new();
        for client in &self.clients {
            let client = client.clone();
            pk_tasks.spawn(async move {
                let endpoint = client.endpoint().to_string();
                let pk = client.get_info().await.ok().and_then(|info| {
                    hex::decode(&info.operator_signing_pk_hex)
                        .ok()
                        .and_then(|bytes| {
                            if bytes.len() == 32 {
                                let mut pk = [0u8; 32];
                                pk.copy_from_slice(&bytes);
                                Some(pk)
                            } else {
                                None
                            }
                        })
                });
                (endpoint, pk)
            });
        }
        let mut operator_pks: HashMap<String, [u8; 32]> = HashMap::new();
        while let Some(joined) = pk_tasks.join_next().await {
            if let Ok((endpoint, Some(pk))) = joined {
                operator_pks.insert(endpoint, pk);
            }
        }

        // Clone each cached object once; tasks then own their inputs.
        let probe_inputs: Vec<([u8; 32], Option<Vec<u8>>)> = all_cids
            .iter()
            .map(|cid| {
                let data = local_objects.and_then(|cache| cache.get(cid)).cloned();
                (*cid, data)
            })
            .collect();
        let mut probe_results: HashMap<[u8; 32], (Vec<String>, Vec<String>)> = HashMap::new();
        for batch in probe_inputs.chunks(8) {
            let mut tasks = JoinSet::new();
            for (cid, data) in batch {
                let cid = *cid;
                let data = data.clone();
                let clients = self.clients.clone();
                let sessions = sessions.clone();
                let operator_pks = operator_pks.clone();
                tasks.spawn(async move {
                    let mut present_on = Vec::new();
                    let mut missing_on = Vec::new();
                    for client in &clients {
                        let ep = client.endpoint();
                        if let Some(token) = sessions.get(ep) {
                            let mut verified = false;

                            // Prefer a lightweight PoS challenge when local bytes exist
                            if let Some(data) = data.as_ref() {
                                if let Some(pk) = operator_pks.get(ep) {
                                    let mut nonce = [0u8; 32];
                                    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
                                    let expected_proof =
                                        ciphervault_storage::compute_pos_proof(&cid, &nonce, data);

                                    if let Ok(receipt) =
                                        client.challenge_object_pos(token, &cid, &nonce).await
                                    {
                                        if receipt.verify(pk, &expected_proof).is_ok() {
                                            verified = true;
                                        }
                                    }
                                }
                            }

                            // If not verified via PoS, fall back to downloading object
                            if !verified {
                                if let Ok(bytes) = client.get_object(token, &cid).await {
                                    if compute_digest(&bytes) == cid {
                                        verified = true;
                                    }
                                }
                            }

                            if verified {
                                present_on.push(ep.to_string());
                            } else {
                                missing_on.push(ep.to_string());
                            }
                        } else {
                            missing_on.push(ep.to_string());
                        }
                    }
                    (cid, present_on, missing_on)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                if let Ok((cid, present_on, missing_on)) = joined {
                    probe_results.insert(cid, (present_on, missing_on));
                }
            }
        }

        for cid in &all_cids {
            let (present_on, missing_on) = probe_results
                .remove(cid)
                .unwrap_or_else(|| (Vec::new(), self.endpoints.clone()));
            for endpoint in &present_on {
                *operator_counts.entry(endpoint.clone()).or_default() += 1;
            }
            if !present_on.is_empty() && present_on.len() == self.clients.len() {
                healthy_count += 1;
            } else if !present_on.is_empty() {
                degraded_count += 1;
                degraded_objects.push(ObjectReplicaStatus {
                    cid: *cid,
                    present_on,
                    missing_on,
                });
            } else {
                lost_count += 1;
                degraded_objects.push(ObjectReplicaStatus {
                    cid: *cid,
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
        let repair_started = std::time::Instant::now();
        let mut objects_repaired = 0;
        let mut objects_failed = 0;
        let mut placement_updates = Vec::new();

        let client_map: HashMap<String, OperatorClient> = self
            .clients
            .iter()
            .map(|c| (c.endpoint().to_string(), c.clone()))
            .collect();

        let mut repair_outcomes: HashMap<[u8; 32], (bool, Vec<PlacementUpdate>)> = HashMap::new();
        for batch in audit.degraded_objects.chunks(4) {
            let mut tasks = JoinSet::new();
            for item in batch {
                let item = item.clone();
                let client_map = client_map.clone();
                let sessions = sessions.clone();
                let signing_key = signing_key.clone();
                let closure_digest = audit.closure_digest;
                tasks.spawn(async move {
                    let outcome = repair_single_object(
                        &client_map,
                        &sessions,
                        &signing_key,
                        closure_digest,
                        &item,
                    )
                    .await;
                    (item.cid, outcome)
                });
            }
            while let Some(joined) = tasks.join_next().await {
                if let Ok((cid, outcome)) = joined {
                    repair_outcomes.insert(cid, outcome);
                }
            }
        }

        for item in &audit.degraded_objects {
            match repair_outcomes.remove(&item.cid) {
                Some((repaired, placements)) => {
                    if repaired {
                        objects_repaired += 1;
                    } else {
                        objects_failed += 1;
                    }
                    placement_updates.extend(placements);
                }
                None => {
                    objects_failed += 1;
                }
            }
        }

        Ok(RepairResult {
            objects_repaired,
            objects_failed,
            placement_updates,
            elapsed_secs: repair_started.elapsed().as_secs(),
        })
    }

    /// Renews lease receipts across operators, ensuring retention runway.
    pub async fn renew_leases(
        &self,
        receipts: &[LeaseReceipt],
        sessions: &HashMap<String, String>,
        additional_days: u32,
    ) -> Vec<LeaseReceipt> {
        let mut info_tasks = JoinSet::new();
        for client in &self.clients {
            let client = client.clone();
            info_tasks.spawn(async move {
                let info = client.get_info().await.ok();
                (client, info.map(|info| info.operator_id))
            });
        }
        let mut op_map: HashMap<String, (OperatorClient, String)> = HashMap::new();
        while let Some(joined) = info_tasks.join_next().await {
            if let Ok((client, Some(operator_id))) = joined {
                if let Some(token) = sessions.get(client.endpoint()) {
                    op_map.insert(operator_id, (client, token.clone()));
                }
            }
        }

        let mut renew_tasks = JoinSet::new();
        for (index, receipt) in receipts.iter().enumerate() {
            if let Some((client, token)) = op_map.get(&receipt.operator_id) {
                let client = client.clone();
                let token = token.clone();
                let lease_id = receipt.lease_id.clone();
                let bytes = receipt.bytes;
                renew_tasks.spawn(async move {
                    let renewed = client
                        .renew_lease(&token, &lease_id, additional_days, bytes)
                        .await
                        .ok();
                    (index, renewed)
                });
            }
        }
        let mut ordered: Vec<(usize, LeaseReceipt)> = Vec::new();
        while let Some(joined) = renew_tasks.join_next().await {
            if let Ok((index, Some(receipt))) = joined {
                ordered.push((index, receipt));
            }
        }
        ordered.sort_by_key(|(index, _)| *index);
        ordered.into_iter().map(|(_, receipt)| receipt).collect()
    }
}

/// Repairs one degraded object: fetches from the first intact operator,
/// verifies integrity, re-uploads to missing operators with readback, and
/// signs placement updates. Returns `(fully_repaired, placement_updates)`.
async fn repair_single_object(
    client_map: &HashMap<String, OperatorClient>,
    sessions: &HashMap<String, String>,
    signing_key: &SigningKey,
    closure_digest: [u8; 32],
    item: &ObjectReplicaStatus,
) -> (bool, Vec<PlacementUpdate>) {
    let mut placement_updates = Vec::new();
    if item.present_on.is_empty() {
        eprintln!(
            "{} Object {} has 0 surviving replicas! Irrecoverable without offline kit.",
            "FATAL:".red().bold(),
            hex::encode(item.cid)
        );
        return (false, placement_updates);
    }

    // Pick first intact operator
    let source_ep = &item.present_on[0];
    let Some(source_token) = sessions.get(source_ep) else {
        return (false, placement_updates);
    };
    let source_client = &client_map[source_ep];

    // Fetch ciphertext bytes from intact operator
    let bytes = match source_client.get_object(source_token, &item.cid).await {
        Ok(b) => b,
        Err(e) => {
            eprintln!(
                "Failed to fetch {} from {}: {}",
                hex::encode(item.cid),
                source_ep,
                e
            );
            return (false, placement_updates);
        }
    };

    // Mandatory SHA-256 integrity verification
    let digest = compute_digest(&bytes);
    if digest != item.cid {
        eprintln!(
            "Integrity mismatch on fetched object {}. Aborting repair for this object.",
            hex::encode(item.cid)
        );
        return (false, placement_updates);
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
        if let Err(e) = target_client
            .put_object(target_token, &item.cid, bytes.clone())
            .await
        {
            eprintln!(
                "Failed to upload {} to {}: {}",
                hex::encode(item.cid),
                target_ep,
                e
            );
            repaired_all = false;
            continue;
        }

        // Verify readback
        match target_client.get_object(target_token, &item.cid).await {
            Ok(readback) if compute_digest(&readback) == item.cid => {
                // Issue signed PlacementUpdate
                let now = Utc::now().timestamp() as u64;
                let msg = format!(
                    "{}:{}:{}:{}",
                    hex::encode(closure_digest),
                    hex::encode(item.cid),
                    target_ep,
                    now
                );
                let sig = sign_with_domain(signing_key, b"placement_update", msg.as_bytes());

                let update = PlacementUpdate {
                    version: PROTOCOL_VERSION,
                    closure_digest: closure_digest.to_vec(),
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

    (repaired_all, placement_updates)
}
