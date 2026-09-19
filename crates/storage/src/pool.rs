use ed25519_dalek::SigningKey;

use crate::client::OperatorClient;
use crate::error::StorageError;
use crate::types::LeaseReceipt;
use futures_util::future::join_all;
use futures_util::stream::{FuturesUnordered, StreamExt};
use std::sync::atomic::{AtomicUsize, Ordering};

/// Default per-operator object concurrency for replication pipelines.
pub const DEFAULT_OBJECT_CONCURRENCY: usize = 4;
/// Upper bound for per-operator object concurrency (`push --concurrency`).
pub const MAX_OBJECT_CONCURRENCY: usize = 32;
/// Default replicas required by `replicate_and_verify` when the caller
/// passes no explicit count (`push --replicas`, `repair --replicas`).
/// Matches the documented 3-operator topology (compose, docs, tests).
pub const DEFAULT_REQUIRED_REPLICAS: usize = 3;

pub struct MultiOperatorPool {
    clients: Vec<OperatorClient>,
    object_concurrency: AtomicUsize,
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
        Self {
            clients,
            object_concurrency: AtomicUsize::new(DEFAULT_OBJECT_CONCURRENCY),
        }
    }

    /// Builds a pool from pre-constructed clients (loopback memory, future
    /// P2P transports). Endpoints are sorted and deduplicated like [`Self::new`].
    pub fn from_clients(mut clients: Vec<OperatorClient>) -> Self {
        clients.sort_by(|a, b| a.endpoint().cmp(b.endpoint()));
        clients.dedup_by(|a, b| a.endpoint() == b.endpoint());
        Self {
            clients,
            object_concurrency: AtomicUsize::new(DEFAULT_OBJECT_CONCURRENCY),
        }
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

    /// Propagates one trace ID to every operator client so spans from a
    /// single push/repair correlate across the quorum (R11).
    pub fn set_trace_id(&self, trace_id: &str) {
        for client in &self.clients {
            client.set_trace_id(trace_id);
        }
    }

    pub fn clear_trace_id(&self) {
        for client in &self.clients {
            client.clear_trace_id();
        }
    }

    /// Bounds how many objects replicate concurrently per operator (1-32).
    pub fn set_object_concurrency(&self, concurrency: usize) {
        self.object_concurrency.store(
            concurrency.clamp(1, MAX_OBJECT_CONCURRENCY),
            Ordering::Relaxed,
        );
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

    /// Replicates the snapshot closure to one authenticated operator: object upload
    /// with PoS deduplication, lease commitment plus signature verification, mandatory
    /// readback verification, and recovery-log publication with discovery readback.
    /// Returns the operator identity key and verified lease receipt on success, or
    /// `None` when this operator must be skipped from quorum accounting.
    #[allow(
        clippy::too_many_arguments,
        reason = "Keep explicit protocol bindings matching replicate_and_verify"
    )]
    async fn replicate_to_single_operator(
        client: &OperatorClient,
        token: &str,
        objects: &[([u8; 32], Vec<u8>)], // (cid, raw_bytes)
        closure_digest: &[u8; 32],
        total_bytes: u64,
        term_days: u32,
        locator: &[u8; 32],
        head_record_bytes: &[u8],
        recovery_records: &[Vec<u8>],
        object_concurrency: usize,
    ) -> Option<([u8; 32], LeaseReceipt)> {
        // 1. Upload all objects (with bandwidth-conserving deduplication via PoS challenge)
        for chunk in objects.chunks(object_concurrency.max(1)) {
            let uploads = chunk.iter().map(|(cid, data)| async move {
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
                if already_present {
                    return Ok(());
                }
                client
                    .put_object(token, cid, data.clone())
                    .await
                    .map_err(|error| {
                        eprintln!(
                            "Upload to {} failed for object {}: {}",
                            client.endpoint(),
                            hex::encode(cid),
                            error
                        );
                    })
            });
            if join_all(uploads).await.iter().any(|result| result.is_err()) {
                return None;
            }
        }

        // 2. Commit lease
        let receipt = match client
            .commit_lease(token, closure_digest, total_bytes, term_days)
            .await
        {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Lease commitment failed on {}: {}", client.endpoint(), e);
                return None;
            }
        };

        // Cryptographically verify operator lease signature
        let Ok(info) = client.get_info().await else {
            return None;
        };
        let Ok(pk_bytes) = hex::decode(&info.operator_signing_pk_hex) else {
            return None;
        };
        let Ok(pk) = <[u8; 32]>::try_from(pk_bytes.as_slice()) else {
            return None;
        };
        if receipt.verify(&pk).is_err()
            || receipt.operator_id != info.operator_id
            || receipt.closure_digest_hex != hex::encode(closure_digest)
            || receipt.bytes != total_bytes
            || receipt.term_days != term_days
        {
            return None;
        }

        // 3. Mandatory Readback Verification (R04) via Bandwidth-Optimized Proof-of-Storage
        for chunk in objects.chunks(object_concurrency.max(1)) {
            let verifications = chunk.iter().map(|(cid, data)| async move {
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
                }
                verified
            });
            if join_all(verifications)
                .await
                .iter()
                .any(|verified| !verified)
            {
                return None;
            }
        }

        // Publish recovery records before the head, and verify discovery readback.
        // A prior interrupted push may have left a partial log (for example a
        // genesis record whose device certificate never landed because quorum
        // early-exit cancelled this operator in flight). The operator then
        // rejects already-registered records with 400 while still accepting
        // the missing suffix, so a rejection must not abort the pipeline: skip
        // the record and let the discovery readback below decide. A rejection
        // proves the operator is alive; transport errors still fail fast.
        for record in recovery_records {
            if let Err(e) = client
                .append_recovery_record(token, locator, record.clone())
                .await
            {
                if matches!(e, StorageError::ServerError { .. }) {
                    eprintln!(
                        "Warning: operator {} rejected a bootstrap record ({}); continuing, discovery readback will decide",
                        client.endpoint(),
                        e
                    );
                    continue;
                }
                return None;
            }
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
            return None;
        }

        let discovered = match client.get_recovery_records(locator).await {
            Ok(d) => d,
            Err(e) => {
                eprintln!(
                    "Warning: discovery readback failed on {}: {}",
                    client.endpoint(),
                    e
                );
                return None;
            }
        };
        if !discovered.iter().any(|r| r == head_record_bytes)
            || !recovery_records.iter().all(|r| discovered.contains(r))
        {
            eprintln!(
                "Warning: discovery mismatch on {}: log holds {} records, {} bootstrap plus head required",
                client.endpoint(),
                discovered.len(),
                recovery_records.len()
            );
            return None;
        }

        Some((pk, receipt))
    }

    /// Replicates a complete snapshot closure across operators with full readback verification.
    /// Per-operator pipelines run concurrently; receipts are sorted by operator ID so
    /// concurrent completion order never leaks into the result.
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

        // Replicate to every authenticated operator concurrently. Each operator's
        // pipeline (upload, lease, readback, recovery log) is independent, so quorum
        // latency becomes the slowest operator instead of the sum of all operators.
        // Completion order also drives quorum-aware early exit: once the remaining
        // operators cannot possibly reach quorum, stragglers are abandoned.
        let object_concurrency = self.object_concurrency.load(Ordering::Relaxed);
        let attempts = sessions.iter().map(|(client, token)| {
            Self::replicate_to_single_operator(
                client,
                token,
                objects,
                closure_digest,
                total_bytes,
                term_days,
                locator,
                head_record_bytes,
                recovery_records,
                object_concurrency,
            )
        });

        let mut pending: FuturesUnordered<_> = attempts.collect();
        let mut verified_receipts = Vec::new();
        let mut verified_keys = std::collections::HashSet::new();
        while let Some(outcome) = pending.next().await {
            if let Some((operator_pk, receipt)) = outcome {
                if verified_keys.insert(operator_pk) {
                    verified_receipts.push(receipt);
                }
            }
            if verified_receipts.len() + pending.len() < required_replicas {
                break;
            }
        }
        // Concurrent tasks complete in nondeterministic order; restore a stable
        // receipt ordering so callers never observe completion order.
        verified_receipts.sort_by(|a, b| a.operator_id.cmp(&b.operator_id));

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
