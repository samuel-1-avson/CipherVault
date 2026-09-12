use ed25519_dalek::SigningKey;

use crate::client::OperatorClient;
use crate::error::StorageError;
use crate::types::LeaseReceipt;

pub struct MultiOperatorPool {
    clients: Vec<OperatorClient>,
}

impl MultiOperatorPool {
    pub fn new(endpoints: Vec<String>) -> Self {
        let mut endpoints: Vec<String> = endpoints
            .into_iter()
            .map(|e| e.trim_end_matches('/').to_string())
            .collect();
        endpoints.sort();
        endpoints.dedup();
        let clients = endpoints.into_iter().map(OperatorClient::new).collect();
        Self { clients }
    }

    pub fn clients(&self) -> &[OperatorClient] {
        &self.clients
    }

    /// Authenticates against all configured operators in parallel.
    /// Returns a list of (OperatorClient, session_token) for successful operators.
    pub async fn authenticate_all(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
    ) -> Vec<(OperatorClient, String)> {
        let mut authenticated = Vec::new();

        for client in &self.clients {
            match client.authenticate(vault_id, signing_key).await {
                Ok(token) => authenticated.push((client.clone(), token)),
                Err(e) => {
                    eprintln!(
                        "Warning: Failed to authenticate with operator {}: {}",
                        client.endpoint(),
                        e
                    );
                }
            }
        }

        authenticated
    }

    /// Replicates a complete snapshot closure across operators with full readback verification.
    /// Returns the verified lease receipts.
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep explicit protocol bindings in the existing public API"
    )]
    pub async fn replicate_and_verify(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
        objects: &[([u8; 32], Vec<u8>)], // (cid, raw_bytes)
        closure_digest: &[u8; 32],
        total_bytes: u64,
        term_days: u32,
        locator: &[u8; 32],
        head_record_bytes: &[u8],
        recovery_records: &[Vec<u8>],
        required_replicas: usize,
    ) -> Result<Vec<LeaseReceipt>, StorageError> {
        let sessions = self.authenticate_all(vault_id, signing_key).await;
        if sessions.len() < required_replicas {
            return Err(StorageError::QuorumDeficit {
                required: required_replicas,
                successful: sessions.len(),
            });
        }

        let mut verified_receipts = Vec::new();
        let mut verified_keys = std::collections::HashSet::new();

        for (client, token) in &sessions {
            let mut operator_ok = true;

            // 1. Upload all objects
            for (cid, data) in objects {
                if let Err(e) = client.put_object(token, cid, data.clone()).await {
                    eprintln!(
                        "Upload to {} failed for object {}: {}",
                        client.endpoint(),
                        hex::encode(cid),
                        e
                    );
                    operator_ok = false;
                    break;
                }
            }

            if !operator_ok {
                continue;
            }

            // 2. Commit lease
            let receipt = match client
                .commit_lease(token, closure_digest, total_bytes, term_days)
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    eprintln!("Lease commitment failed on {}: {}", client.endpoint(), e);
                    continue;
                }
            };

            // Cryptographically verify operator lease signature
            let Ok(info) = client.get_info().await else {
                continue;
            };
            let Ok(pk_bytes) = hex::decode(&info.operator_signing_pk_hex) else {
                continue;
            };
            let Ok(pk) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
                continue;
            };
            if receipt.verify(&pk).is_err()
                || receipt.operator_id != info.operator_id
                || receipt.closure_digest_hex != hex::encode(closure_digest)
                || receipt.bytes != total_bytes
                || receipt.term_days != term_days
            {
                continue;
            }

            // 3. Mandatory Readback Verification (R04)
            for (cid, _) in objects {
                if let Err(e) = client.get_object(token, cid).await {
                    eprintln!(
                        "Readback verification failed on {} for {}: {}",
                        client.endpoint(),
                        hex::encode(cid),
                        e
                    );
                    operator_ok = false;
                    break;
                }
            }

            if !operator_ok {
                continue;
            }

            // Publish bootstrap records before the head, and verify discovery readback.
            for record in recovery_records {
                if client
                    .append_recovery_record(token, locator, record.clone())
                    .await
                    .is_err()
                {
                    operator_ok = false;
                    break;
                }
            }
            if !operator_ok {
                continue;
            }
            // 4. Append head record to recovery log
            if let Err(e) = client
                .append_recovery_record(token, locator, head_record_bytes.to_vec())
                .await
            {
                eprintln!(
                    "Failed to append recovery head record on {}: {}",
                    client.endpoint(),
                    e
                );
                continue;
            }

            let Ok(discovered) = client.get_recovery_records(locator).await else {
                continue;
            };
            if !discovered.iter().any(|r| r == head_record_bytes)
                || !recovery_records.iter().all(|r| discovered.contains(r))
            {
                continue;
            }

            if verified_keys.insert(pk) {
                verified_receipts.push(receipt);
            }
        }

        if verified_receipts.len() < required_replicas {
            return Err(StorageError::QuorumDeficit {
                required: required_replicas,
                successful: verified_receipts.len(),
            });
        }

        Ok(verified_receipts)
    }

    /// Queries all surviving operators for recovery records (candidate heads and envelopes).
    pub async fn query_recovery_records(&self, locator: &[u8; 32]) -> Vec<Vec<u8>> {
        let mut all_records = Vec::new();

        for client in &self.clients {
            if let Ok(records) = client.get_recovery_records(locator).await {
                for r in records {
                    if !all_records.contains(&r) {
                        all_records.push(r);
                    }
                }
            }
        }

        all_records
    }

    /// Fetches an object by CID from any available operator in the pool.
    pub async fn fetch_object_from_any(&self, cid: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        for client in &self.clients {
            // For public recovery fetch or with open access
            if let Ok(bytes) = client.get_object("recovery_anonymous", cid).await {
                return Ok(bytes);
            }
        }
        Err(StorageError::OperatorUnreachable {
            endpoint: "all".into(),
            details: format!(
                "Object {} not found on any surviving operator",
                hex::encode(cid)
            ),
        })
    }
}
