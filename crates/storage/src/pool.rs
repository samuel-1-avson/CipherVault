use ed25519_dalek::SigningKey;

use crate::client::OperatorClient;
use crate::error::StorageError;
use crate::types::LeaseReceipt;
use futures_util::future::join_all;

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

    pub fn endpoints(&self) -> Vec<String> {
        self.clients
            .iter()
            .map(|c| c.endpoint().to_string())
            .collect()
    }

    /// Propagates the optional account/device identity to every operator
    /// client so challenge issuance and subsequent requests carry the same
    /// device-registry binding.
    pub fn set_account_identity(&self, account_id: &str, device_id_hex: &str) {
        for client in &self.clients {
            client.with_account_identity(account_id, device_id_hex);
        }
    }

    pub fn clear_account_identity(&self) {
        for client in &self.clients {
            client.clear_account_identity();
        }
    }

    /// Discovers active peer operators from current endpoints via P2P gossip and dynamically expands the pool.
    /// Returns the number of newly discovered and verified peer operators.
    pub async fn discover_and_expand_peers(&mut self) -> Result<usize, StorageError> {
        let mut new_endpoints = Vec::new();
        let existing: std::collections::HashSet<String> = self
            .clients
            .iter()
            .map(|c| c.endpoint().trim_end_matches('/').to_string())
            .collect();

        for client in &self.clients {
            if let Ok(peers) = client.get_peers().await {
                for peer in peers {
                    if peer.verify().is_ok() {
                        let normalized = peer.endpoint.trim_end_matches('/').to_string();
                        if !existing.contains(&normalized) && !new_endpoints.contains(&normalized) {
                            new_endpoints.push(normalized);
                        }
                    }
                }
            }
        }

        let count = new_endpoints.len();
        for endpoint in new_endpoints {
            self.clients.push(OperatorClient::new(endpoint));
        }

        Ok(count)
    }

    /// Authenticates against all configured operators in parallel.
    /// Returns a list of (OperatorClient, session_token) for successful operators.
    pub async fn authenticate_all(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
    ) -> Vec<(OperatorClient, String)> {
        let attempts = self.clients.iter().cloned().map(|client| async move {
            let result = client.authenticate(vault_id, signing_key).await;
            (client, result)
        });
        let mut authenticated = Vec::new();
        for (client, result) in join_all(attempts).await {
            match result {
                Ok(token) => authenticated.push((client, token)),
                Err(e) => eprintln!(
                    "Warning: Failed to authenticate with operator {}: {}",
                    client.endpoint(),
                    e
                ),
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

            // 1. Upload all objects (with bandwidth-conserving deduplication via PoS challenge)
            for (cid, data) in objects {
                let mut challenge_nonce = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut challenge_nonce);
                let expected_proof = crate::compute_pos_proof(cid, &challenge_nonce, data);

                let already_present = match client
                    .challenge_object_pos(token, cid, &challenge_nonce)
                    .await
                {
                    Ok(proof) => proof.proof_hex == hex::encode(expected_proof),
                    Err(_) => false,
                };

                if !already_present {
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

            // 3. Mandatory Readback Verification (R04) via Bandwidth-Optimized Proof-of-Storage
            for (cid, data) in objects {
                let mut nonce = [0u8; 32];
                rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut nonce);
                let expected_proof = crate::compute_pos_proof(cid, &nonce, data);

                let verified = match client.challenge_object_pos(token, cid, &nonce).await {
                    Ok(receipt) => receipt.verify(&pk, &expected_proof).is_ok(),
                    Err(_) => {
                        // Transparent fallback to full object readback for older operator versions
                        match client.get_object(token, cid).await {
                            Ok(bytes) => ciphervault_format::compute_digest(&bytes) == *cid,
                            Err(_) => false,
                        }
                    }
                };

                if !verified {
                    eprintln!(
                        "Readback verification failed on {} for {}",
                        client.endpoint(),
                        hex::encode(cid),
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
        let queries = self
            .clients
            .iter()
            .cloned()
            .map(|client| async move { client.get_recovery_records(locator).await });
        let mut all_records = Vec::new();
        for records in join_all(queries).await.into_iter().flatten() {
            for record in records {
                if !all_records.contains(&record) {
                    all_records.push(record);
                }
            }
        }
        all_records
    }

    /// Fetches an object by CID from any available operator in the pool.
    pub async fn fetch_object_from_any(&self, cid: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let queries = self.clients.iter().cloned().map(|client| async move {
            // For public recovery fetch or with open access
            client.get_object("recovery_anonymous", cid).await
        });
        if let Some(bytes) = join_all(queries).await.into_iter().flatten().next() {
            return Ok(bytes);
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
