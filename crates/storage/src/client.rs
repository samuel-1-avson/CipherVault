use std::time::Duration;
use ed25519_dalek::SigningKey;
use reqwest::{header, Client};

use ciphervault_crypto::signatures::sign_with_domain;
use ciphervault_format::compute_digest;

use crate::error::StorageError;
use crate::types::{
    AppendRecordResponse, ChallengeRequest, ChallengeResponse, LeaseReceipt, LeaseRequest,
    OperatorInfo, RecoveryRecordsResponse, SessionRequest, SessionResponse,
};

#[derive(Clone)]
pub struct OperatorClient {
    endpoint: String,
    http: Client,
}

impl OperatorClient {
    pub fn new(endpoint: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            endpoint: endpoint.trim_end_matches('/').to_string(),
            http,
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
        Ok(info)
    }

    pub async fn authenticate(
        &self,
        vault_id: &[u8; 32],
        signing_key: &SigningKey,
    ) -> Result<String, StorageError> {
        let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
        let vault_hex = hex::encode(vault_id);

        // 1. Request challenge
        let challenge_url = format!("{}/v1/challenges", self.endpoint);
        let c_resp = self
            .http
            .post(&challenge_url)
            .json(&ChallengeRequest {
                vault_id_hex: vault_hex,
                public_key_hex: pk_hex.clone(),
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
        let nonce_bytes = hex::decode(&challenge.nonce_hex)
            .map_err(|e| StorageError::ServerError { status: 500, message: e.to_string() })?;
        let sig = sign_with_domain(signing_key, b"operator_challenge", &nonce_bytes);
        let sig_hex = hex::encode(sig);

        // 3. Redeem session
        let session_url = format!("{}/v1/sessions", self.endpoint);
        let s_resp = self
            .http
            .post(&session_url)
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
            .http
            .put(&url)
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

    pub async fn get_object(&self, token: &str, cid: &[u8; 32]) -> Result<Vec<u8>, StorageError> {
        let cid_hex = hex::encode(cid);
        let url = format!("{}/v1/objects/{}", self.endpoint, cid_hex);

        let resp = self
            .http
            .get(&url)
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

    pub async fn commit_lease(
        &self,
        token: &str,
        closure_digest: &[u8; 32],
        byte_count: u64,
        term_days: u32,
    ) -> Result<LeaseReceipt, StorageError> {
        let url = format!("{}/v1/leases", self.endpoint);
        let resp = self
            .http
            .post(&url)
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
            .http
            .post(&url)
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
            .http
            .post(&url)
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
            let b = hex::decode(r_hex)
                .map_err(|e| StorageError::ServerError { status: 500, message: e.to_string() })?;
            out.push(b);
        }
        Ok(out)
    }
}
