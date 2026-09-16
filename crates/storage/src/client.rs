use ed25519_dalek::SigningKey;
use reqwest::{header, Client};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::compute_digest;

use crate::error::StorageError;
use crate::types::{
    AppendRecordResponse, ChallengeRequest, ChallengeResponse, LeaseReceipt, LeaseRequest,
    OperatorInfo, PosChallengeRequest, ProofOfStorageReceipt, RecoveryRecordsResponse,
    SessionRequest, SessionResponse,
};

#[derive(Clone)]
pub struct OperatorClient {
    endpoint: String,
    http: Client,
    vault_scope: Arc<Mutex<Option<String>>>,
    account_identity: Arc<Mutex<Option<(String, String)>>>,
    trace_id: Arc<Mutex<Option<String>>>,
}

impl OperatorClient {
    pub fn new(endpoint: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self::with_http_client(endpoint, http)
    }

    /// Creates a client using a caller-owned HTTP pool. Cloning `reqwest::Client`
    /// shares its connection pool, allowing recurring probes to reuse TCP
    /// connections instead of paying a cross-region handshake every sample.
    pub fn with_http_client(endpoint: String, http: Client) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
            vault_scope: Arc::new(Mutex::new(None)),
            account_identity: Arc::new(Mutex::new(None)),
            trace_id: Arc::new(Mutex::new(None)),
        }
    }

    /// Binds operator sessions to the optional CipherVault account/device
    /// registry. The values are identifiers only; no account or vault secret
    /// is sent to an operator.
    pub fn with_account_identity(
        &self,
        account_id: impl Into<String>,
        device_id_hex: impl Into<String>,
    ) {
        if let Ok(mut identity) = self.account_identity.lock() {
            *identity = Some((
                account_id.into().trim().to_ascii_lowercase(),
                device_id_hex.into().trim().to_ascii_lowercase(),
            ));
        }
    }

    pub fn clear_account_identity(&self) {
        if let Ok(mut identity) = self.account_identity.lock() {
            *identity = None;
        }
    }

    /// Generates a random 128-bit trace ID (32 hex chars) correlating one
    /// CLI/fleet operation across operator spans (R11).
    pub fn new_trace_id() -> String {
        hex::encode(rand::random::<[u8; 16]>())
    }

    /// Sets the trace ID attached to every subsequent request.
    pub fn set_trace_id(&self, trace_id: &str) {
        if let Ok(mut current) = self.trace_id.lock() {
            *current = Some(trace_id.trim().to_ascii_lowercase());
        }
    }

    /// Returns the currently configured trace ID, if any.
    pub fn trace_id(&self) -> Option<String> {
        self.trace_id.lock().ok().and_then(|id| id.clone())
    }

    pub fn clear_trace_id(&self) {
        if let Ok(mut current) = self.trace_id.lock() {
            *current = None;
        }
    }

    fn account_identity(&self) -> Option<(String, String)> {
        self.account_identity
            .lock()
            .ok()
            .and_then(|identity| identity.clone())
    }

    fn with_identity_binding(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match self.account_identity() {
            Some((account_id, device_id_hex)) => request
                .header("X-CipherVault-Account-Id", account_id)
                .header("X-CipherVault-Device-Id", device_id_hex),
            None => request,
        }
    }

    fn with_vault_scope(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        let request = match self.vault_scope.lock().ok().and_then(|scope| scope.clone()) {
            Some(scope) => request.header("X-CipherVault-Id", scope),
            None => request,
        };
        let request = match self.trace_id.lock().ok().and_then(|id| id.clone()) {
            Some(trace_id) => request.header("X-CipherVault-Trace-Id", trace_id),
            None => request,
        };
        self.with_identity_binding(request)
    }

    fn with_service_token(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
            Ok(token) if !token.is_empty() => request.header("X-CipherVault-Service-Token", token),
            _ => request,
        }
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn get_info(&self) -> Result<OperatorInfo, StorageError> {
        let url = format!("{}/v1/info", self.endpoint);
        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        let info = resp.json::<OperatorInfo>().await?;
        if !info.identity_signature_hex.is_empty() && !info.verify_identity_signature() {
            return Err(StorageError::ServerError {
                status: 502,
                message: "Operator identity signature verification failed".into(),
            });
        }
        Ok(info)
    }

    /// Fetches and verifies an operator identity against a caller-supplied pinned key.
    /// This is the strict path used when a vault has an enrolled operator registry.
    pub async fn get_info_pinned(
        &self,
        expected_signing_key: &[u8; 32],
    ) -> Result<OperatorInfo, StorageError> {
        let info = self.get_info().await?;
        let expected_hex = hex::encode(expected_signing_key);
        if !info
            .operator_signing_pk_hex
            .eq_ignore_ascii_case(&expected_hex)
            || !info.verify_identity_signature()
        {
            return Err(StorageError::ServerError {
                status: 502,
                message: "Operator identity does not match the pinned signing key".into(),
            });
        }
        if info.identity_expires_at_utc != 0
            && chrono::Utc::now().timestamp() as u64 > info.identity_expires_at_utc
        {
            return Err(StorageError::ServerError {
                status: 502,
                message: "Operator identity descriptor has expired".into(),
            });
        }
        Ok(info)
    }

    pub async fn authenticate(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
    ) -> Result<String, StorageError> {
        let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let vault_hex = hex::encode(vault_id);
        let identity = self.account_identity();

        // 1. Request challenge
        let challenge_url = format!("{}/v1/challenges", self.endpoint);
        let c_resp = self
            .with_identity_binding(self.http.post(&challenge_url))
            .json(&ChallengeRequest {
                vault_id_hex: vault_hex.clone(),
                public_key_hex: pk_hex.clone(),
                account_id: identity.as_ref().map(|(account_id, _)| account_id.clone()),
                device_id_hex: identity.as_ref().map(|(_, device_id)| device_id.clone()),
            })
            .send()
            .await?;

        if !c_resp.status().is_success() {
            let status = c_resp.status().as_u16();
            let message = c_resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        let challenge = c_resp.json::<ChallengeResponse>().await?;

        // 2. Sign challenge nonce
        let nonce_bytes =
            hex::decode(&challenge.nonce_hex).map_err(|e| StorageError::ServerError {
                status: 500,
                message: e.to_string(),
            })?;
        let sig = sign_with_domain(signing_key, b"operator_challenge", &nonce_bytes);
        let sig_hex = hex::encode(sig);

        // 3. Redeem session
        let session_url = format!("{}/v1/sessions", self.endpoint);
        let s_resp = self
            .with_identity_binding(self.http.post(&session_url))
            .json(&SessionRequest {
                challenge_id: challenge.challenge_id,
                public_key_hex: pk_hex,
                signature_hex: sig_hex,
            })
            .send()
            .await?;

        if !s_resp.status().is_success() {
            let status = s_resp.status().as_u16();
            let message = s_resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        let session = s_resp.json::<SessionResponse>().await?;
        if let Ok(mut scope) = self.vault_scope.lock() {
            *scope = Some(vault_hex);
        }
        Ok(session.token)
    }

    pub async fn put_object(
        &self,
        token: &str,
        cid: &[u8; 32],
        data: Vec<u8>,
    ) -> Result<(), StorageError> {
        let cid_hex = hex::encode(cid);
        let url = format!("{}/v1/objects/{}", self.endpoint, cid_hex);

        let resp = self
            .with_vault_scope(self.http.put(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(data)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        Ok(())
    }

    pub async fn revoke_session(&self, token: &str) -> Result<(), StorageError> {
        let url = format!("{}/v1/sessions/revoke", self.endpoint);
        let resp = self
            .with_vault_scope(self.http.post(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        Ok(())
    }

    pub async fn get_object(&self, token: &str, cid: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let cid_hex = hex::encode(cid);
        let url = format!("{}/v1/objects/{}", self.endpoint, cid_hex);

        let resp = self
            .with_vault_scope(self.http.get(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let bytes = resp.bytes().await?.to_vec();
        let actual_digest = compute_digest(&bytes);

        if actual_digest != *cid {
            return Err(StorageError::DigestMismatch {
                cid: cid_hex,
                expected: hex::encode(cid),
                actual: hex::encode(actual_digest),
            });
        }

        Ok(bytes)
    }

    /// Issues a lightweight Proof-of-Storage challenge to verify that an operator possesses
    /// an object without transmitting the entire payload over the network.
    pub async fn challenge_object_pos(
        &self,
        token: &str,
        cid: &[u8; 32],
        nonce: &[u8; 32],
    ) -> Result<ProofOfStorageReceipt, StorageError> {
        let cid_hex = hex::encode(cid);
        let url = format!("{}/v1/objects/{}/challenge", self.endpoint, cid_hex);

        let resp = self
            .with_vault_scope(self.http.post(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(&PosChallengeRequest {
                nonce_hex: hex::encode(nonce),
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let receipt = resp.json::<ProofOfStorageReceipt>().await?;
        Ok(receipt)
    }

    pub async fn commit_lease(
        &self,
        token: &str,
        closure_digest: &[u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, StorageError> {
        let url = format!("{}/v1/leases", self.endpoint);
        let resp = self
            .with_vault_scope(self.http.post(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(&LeaseRequest {
                closure_digest_hex: hex::encode(closure_digest),
                byte_count,
                term_days,
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let receipt = resp.json::<LeaseReceipt>().await?;
        Ok(receipt)
    }

    pub async fn renew_lease(
        &self,
        token: &str,
        lease_id: &str,
        additional_days: u32,
        byte_count: u64,
    ) -> Result<LeaseReceipt, StorageError> {
        let url = format!("{}/v1/leases/{}/renew", self.endpoint, lease_id);
        let resp = self
            .with_vault_scope(self.http.post(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .json(&crate::types::LeaseRenewRequest {
                additional_days,
                byte_count,
            })
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let receipt = resp.json::<LeaseReceipt>().await?;
        Ok(receipt)
    }

    pub async fn append_recovery_record(
        &self,
        token: &str,
        locator: &[u8; 32],
        record_bytes: Vec<u8>,
    ) -> Result<u64, StorageError> {
        let locator_hex = hex::encode(locator);
        let url = format!("{}/v1/recovery/{}/records", self.endpoint, locator_hex);

        let resp = self
            .with_vault_scope(self.http.post(&url))
            .header(header::AUTHORIZATION, format!("Bearer {}", token))
            .header(header::CONTENT_TYPE, "application/octet-stream")
            .body(record_bytes)
            .send()
            .await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let result = resp.json::<AppendRecordResponse>().await?;
        Ok(result.sequence)
    }

    pub async fn get_recovery_records(
        &self,
        locator: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        let locator_hex = hex::encode(locator);
        let url = format!("{}/v1/recovery/{}/records", self.endpoint, locator_hex);

        let resp = self.http.get(&url).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let body = resp.json::<RecoveryRecordsResponse>().await?;
        let mut out = Vec::new();
        for r_hex in body.records_hex {
            let b = hex::decode(r_hex).map_err(|e| StorageError::ServerError {
                status: 500,
                message: e.to_string(),
            })?;
            out.push(b);
        }
        Ok(out)
    }

    pub async fn announce_peer(
        &self,
        descriptor: &crate::types::PeerDescriptor,
    ) -> Result<(), StorageError> {
        let url = format!("{}/v1/peers/announce", self.endpoint);
        let resp = self
            .with_service_token(self.http.post(&url))
            .json(descriptor)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        Ok(())
    }

    pub async fn get_peers(&self) -> Result<Vec<crate::types::PeerDescriptor>, StorageError> {
        let url = format!("{}/v1/peers", self.endpoint);
        let resp = self.with_service_token(self.http.get(&url)).send().await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }
        let peers = resp.json::<Vec<crate::types::PeerDescriptor>>().await?;
        Ok(peers)
    }
}

#[cfg(test)]
mod tests {
    use super::OperatorClient;

    #[test]
    fn trace_id_round_trip_and_format() {
        let id = OperatorClient::new_trace_id();
        assert_eq!(id.len(), 32);
        assert!(id.bytes().all(|byte| byte.is_ascii_hexdigit()));
        let client = OperatorClient::new("http://127.0.0.1:9".into());
        assert!(client.trace_id().is_none());
        client.set_trace_id(&id);
        assert_eq!(client.trace_id().as_deref(), Some(id.as_str()));
        client.clear_trace_id();
        assert!(client.trace_id().is_none());
    }
}
