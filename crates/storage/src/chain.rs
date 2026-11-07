//! Sovereign CipherChain anchor client.
//!
//! Ethereum/Arbitrum anchoring was removed in Phase 1 of the sovereign-chain
//! migration. The legacy EVM stack (`ArbitrumAnchorClient`, `AnchorRelayerClient`,
//! `CipherVaultRegistry.sol`, `foundry.toml`) is preserved in git tag
//! `last-evm-anchor` for auditors verifying historical anchors. This module now
//! exposes only the sovereign path: submitting commitments to, and verifying
//! inclusion proofs from, CipherVault's native Proof-of-Authority ledger.

use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::time::Duration;

use crate::error::StorageError;

/// Re-exported sovereign ledger primitives.
pub use ciphervault_chain::{
    AnchorProofResponse, BlockHeader, BlockSignature, CipherChainBlock, CommitmentTx,
    ConsensusSigner, InclusionProof, SovereignLedger, SovereignLightClient,
    SovereignVerificationResult, ValidatorSet,
};

/// Sovereign Anchor Verification Report for CipherVault's native blockchain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SovereignAnchorReport {
    pub chain_id: String,
    pub height: u64,
    pub block_hash_hex: String,
    pub timestamp_ms: u64,
    pub commitment_hex: String,
    pub head_cid_hex: String,
    pub proposer_hex: String,
    pub signatures_verified: usize,
    pub quorum_required: usize,
    pub preimage_valid: bool,
    pub merkle_verified: bool,
    pub confirmed: bool,
    pub message: String,
}

/// Sovereign Anchor Client interacting with CipherVault's native blockchain network.
#[derive(Clone)]
pub struct SovereignAnchorClient {
    endpoint_url: String,
    chain_id: String,
    light_client: SovereignLightClient,
    http: Client,
}

impl SovereignAnchorClient {
    pub fn new(endpoint_url: String, chain_id: String, trusted_validators: Vec<[u8; 32]>) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        let light_client = SovereignLightClient::new(&chain_id, trusted_validators);
        Self {
            endpoint_url: endpoint_url.trim_end_matches('/').to_string(),
            chain_id,
            light_client,
            http,
        }
    }

    pub fn endpoint_url(&self) -> &str {
        &self.endpoint_url
    }

    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    pub fn light_client(&self) -> &SovereignLightClient {
        &self.light_client
    }

    /// Submits a commitment transaction to the sovereign blockchain network.
    pub async fn submit_commitment(
        &self,
        tx: &CommitmentTx,
    ) -> Result<AnchorProofResponse, StorageError> {
        let url = format!("{}/v1/chain/commitments", self.endpoint_url);
        let resp = self.http.post(&url).json(tx).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let proof: AnchorProofResponse = resp.json().await?;
        Ok(proof)
    }

    /// Fetches and verifies anchor inclusion proof from the sovereign blockchain network.
    pub async fn fetch_and_verify_anchor(
        &self,
        head_cid: &[u8; 32],
        salt: &[u8; 32],
    ) -> Result<SovereignAnchorReport, StorageError> {
        let commitment = CommitmentTx::calculate_commitment(salt, head_cid);
        let url = format!(
            "{}/v1/chain/proofs/{}",
            self.endpoint_url,
            hex::encode(commitment)
        );

        let resp = self.http.get(&url).send().await?;

        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let message = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError { status, message });
        }

        let proof: AnchorProofResponse = resp.json().await?;

        let res = self.light_client.verify_anchor(head_cid, salt, &proof)?;

        Ok(SovereignAnchorReport {
            chain_id: res.chain_id,
            height: res.height,
            block_hash_hex: res.block_hash_hex,
            timestamp_ms: res.timestamp_ms,
            commitment_hex: res.commitment_hex,
            head_cid_hex: res.head_cid_hex,
            proposer_hex: res.proposer_hex,
            signatures_verified: res.signatures_verified,
            quorum_required: res.quorum_required,
            preimage_valid: true,
            merkle_verified: true,
            confirmed: res.verified,
            message: res.message,
        })
    }
}
