use ed25519_dalek::SigningKey;
use reqwest::Client;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::compute_digest;

use crate::error::StorageError;
use crate::transport::{HttpTransport, OperatorTransport, SharedIdentity, SharedScope};
use crate::types::{
    ChallengeRequest, LeaseReceipt, OperatorInfo, ProofOfStorageReceipt, SessionRequest,
};

#[derive(Clone)]
pub struct OperatorClient {
    endpoint: String,
    transport: Arc<dyn OperatorTransport>,
    vault_scope: SharedScope,
    account_identity: SharedIdentity,
    trace_id: SharedScope,
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
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let vault_scope = Arc::new(Mutex::new(None));
        let account_identity = Arc::new(Mutex::new(None));
        let trace_id = Arc::new(Mutex::new(None));
        let transport = HttpTransport::with_shared(
            endpoint.clone(),
            http,
            Arc::clone(&vault_scope),
            Arc::clone(&account_identity),
            Arc::clone(&trace_id),
        );
        Self {
            endpoint,
            transport: Arc::new(transport),
            vault_scope,
            account_identity,
            trace_id,
        }
    }

    /// Creates a client over an explicit transport (loopback memory, future
    /// P2P streams). Identity/trace setters keep working; transports that do
    /// not need them simply ignore the shared state.
    pub fn with_transport(endpoint: String, transport: Arc<dyn OperatorTransport>) -> Self {
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            transport,
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

    /// Stages the write voucher attached to subsequent requests (`None`
    /// clears it). Each operator honors only vouchers it issued itself,
    /// so multi-operator callers stage a different voucher per client.
    pub fn set_write_voucher(&self, voucher: Option<crate::vouchers::WriteVoucher>) {
        self.transport.set_write_voucher(voucher);
    }

    fn account_identity(&self) -> Option<(String, String)> {
        self.account_identity
            .lock()
            .ok()
            .and_then(|identity| identity.clone())
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub async fn get_info(&self) -> Result<OperatorInfo, StorageError> {
        let info = self.transport.fetch_info().await?;
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
        let challenge = self
            .transport
            .request_challenge(ChallengeRequest {
                vault_id_hex: vault_hex.clone(),
                public_key_hex: pk_hex.clone(),
                account_id: identity.as_ref().map(|(account_id, _)| account_id.clone()),
                device_id_hex: identity.as_ref().map(|(_, device_id)| device_id.clone()),
            })
            .await?;

        // 2. Sign challenge nonce
        let nonce_bytes =
            hex::decode(&challenge.nonce_hex).map_err(|e| StorageError::ServerError {
                status: 500,
                message: e.to_string(),
            })?;
        let sig = sign_with_domain(signing_key, b"operator_challenge", &nonce_bytes);
        let sig_hex = hex::encode(sig);

        // 3. Redeem session
        let session = self
            .transport
            .redeem_session(SessionRequest {
                challenge_id: challenge.challenge_id,
                public_key_hex: pk_hex,
                signature_hex: sig_hex,
            })
            .await?;
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
        self.transport.put_object(token, cid, data).await
    }

    pub async fn revoke_session(&self, token: &str) -> Result<(), StorageError> {
        self.transport.revoke_session(token).await
    }

    pub async fn get_object(&self, token: &str, cid: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let bytes = self.transport.fetch_object_bytes(token, cid).await?;
        let actual_digest = compute_digest(&bytes);

        if actual_digest != *cid {
            let cid_hex = hex::encode(cid);
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
        self.transport.challenge_object_pos(token, cid, nonce).await
    }

    pub async fn commit_lease(
        &self,
        token: &str,
        closure_digest: &[u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, StorageError> {
        self.transport
            .commit_lease(token, closure_digest, byte_count, term_days)
            .await
    }

    pub async fn renew_lease(
        &self,
        token: &str,
        lease_id: &str,
        additional_days: u32,
        byte_count: u64,
    ) -> Result<LeaseReceipt, StorageError> {
        self.transport
            .renew_lease(token, lease_id, additional_days, byte_count)
            .await
    }

    pub async fn append_recovery_record(
        &self,
        token: &str,
        locator: &[u8; 32],
        record_bytes: Vec<u8>,
    ) -> Result<u64, StorageError> {
        self.transport
            .append_recovery_record(token, locator, record_bytes)
            .await
    }

    pub async fn get_recovery_records(
        &self,
        locator: &[u8; 32],
    ) -> Result<Vec<Vec<u8>>, StorageError> {
        self.transport.get_recovery_records(locator).await
    }

    pub async fn announce_peer(
        &self,
        descriptor: &crate::types::PeerDescriptor,
    ) -> Result<(), StorageError> {
        self.transport.announce_peer(descriptor).await
    }

    pub async fn get_peers(&self) -> Result<Vec<crate::types::PeerDescriptor>, StorageError> {
        self.transport.get_peers().await
    }

    /// Presents a verified-join ticket to a fleet node. Public route: the
    /// fleet-signed invite is the authorization, no service token attached.
    pub async fn join_with_invite(
        &self,
        descriptor: &crate::types::PeerDescriptor,
        invite: &crate::invites::JoinInvite,
    ) -> Result<crate::invites::JoinResponse, StorageError> {
        self.transport.join_with_invite(descriptor, invite).await
    }

    /// Re-presents a fresh self-signed descriptor to prove liveness of an
    /// already-joined node key. Public route, no service token attached.
    pub async fn refresh_join(
        &self,
        descriptor: &crate::types::PeerDescriptor,
    ) -> Result<(), StorageError> {
        self.transport.refresh_join(descriptor).await
    }

    /// Fetches pending out-of-band approval challenges (R14 dashboard queue).
    /// Control-plane route: authenticates with the operator service token.
    pub async fn get_pending_approvals(
        &self,
    ) -> Result<Vec<crate::types::PendingApprovalChallenge>, StorageError> {
        self.transport.get_pending_approvals().await
    }

    /// Issues a self-signed write voucher from the operator (D4 barter).
    /// Operator-local administration: service-token auth, HTTP only.
    pub async fn issue_voucher(
        &self,
        holder_pk_hex: &str,
        quota_bytes: u64,
        ttl_secs: u64,
    ) -> Result<crate::vouchers::WriteVoucher, StorageError> {
        self.transport
            .issue_voucher(holder_pk_hex, quota_bytes, ttl_secs)
            .await
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
