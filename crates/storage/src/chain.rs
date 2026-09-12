use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::time::Duration;

use ciphervault_format::CheckpointEvidence;
use crate::error::StorageError;

/// Status of an Arbitrum checkpoint anchoring.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnchorFinalityStage {
    /// In local queue or submitted to relayer, pending block inclusion.
    Pending,
    /// Included in Arbitrum L2 block (Sequencer confirmation).
    SequencerConfirmed { block_number: u64 },
    /// Posted to Ethereum L1 parent chain data availability batch.
    ParentDataFinalized { block_number: u64 },
    /// Challenge period expired; rollup assertion settled.
    AssertionSettled { block_number: u64 },
}

/// Verified on-chain transaction receipt from Ethereum/Arbitrum RPC.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionReceipt {
    pub transaction_hash: [u8; 32],
    pub block_number: u64,
    pub status: bool,
}

/// Verification report for an on-chain checkpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnchorVerificationReport {
    pub commitment_hex: String,
    pub preimage_valid: bool,
    pub contract_address_hex: String,
    pub chain_id: u64,
    pub recorded_block_number: u64,
    pub current_chain_block: u64,
    pub finality_stage: AnchorFinalityStage,
    pub on_chain_confirmed: bool,
    pub tx_hash_hex: String,
}

/// Client for interacting with the Arbitrum CipherVaultRegistry contract.
#[derive(Clone)]
pub struct ArbitrumAnchorClient {
    rpc_url: String,
    chain_id: u64,
    contract_address: [u8; 20],
    http: Client,
}

impl ArbitrumAnchorClient {
    pub fn new(rpc_url: String, chain_id: u64, contract_address: [u8; 20]) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            rpc_url: rpc_url.trim_end_matches('/').to_string(),
            chain_id,
            contract_address,
            http,
        }
    }

    pub fn contract_address(&self) -> &[u8; 20] {
        &self.contract_address
    }

    pub fn chain_id(&self) -> u64 {
        self.chain_id
    }

    /// Computes function selector: `keccak256(signature)[0..4]`.
    pub fn compute_selector(signature: &str) -> [u8; 4] {
        let mut hasher = Keccak256::new();
        hasher.update(signature.as_bytes());
        let hash = hasher.finalize();
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&hash[0..4]);
        selector
    }

    /// Encodes calldata for `publish(bytes32)`.
    pub fn encode_publish_calldata(commitment: &[u8; 32]) -> Vec<u8> {
        let selector = Self::compute_selector("publish(bytes32)");
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(commitment);
        calldata
    }

    /// Encodes calldata for `getFirstSeenBlock(bytes32)`.
    pub fn encode_get_first_seen_calldata(commitment: &[u8; 32]) -> Vec<u8> {
        let selector = Self::compute_selector("getFirstSeenBlock(bytes32)");
        let mut calldata = Vec::with_capacity(36);
        calldata.extend_from_slice(&selector);
        calldata.extend_from_slice(commitment);
        calldata
    }

    /// Queries the current block number via JSON-RPC `eth_blockNumber`.
    pub async fn get_block_number(&self) -> Result<u64, StorageError> {
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_blockNumber",
            "params": [],
            "id": 1
        });

        let resp = self.http.post(&self.rpc_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(StorageError::ServerError {
                status: resp.status().as_u16(),
                message: "Failed to fetch block number".into(),
            });
        }

        let body: serde_json::Value = resp.json().await?;
        let hex_str = body["result"]
            .as_str()
            .ok_or_else(|| StorageError::ServerError {
                status: 500,
                message: "Missing result in eth_blockNumber".into(),
            })?;

        let block = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16)
            .map_err(|e| StorageError::ServerError {
                status: 500,
                message: format!("Invalid hex block number: {}", e),
            })?;

        Ok(block)
    }

    /// Queries the first-seen block number of a commitment from the contract.
    pub async fn query_first_seen_block(
        &self,
        commitment: &[u8; 32],
    ) -> Result<Option<u64>, StorageError> {
        let calldata = Self::encode_get_first_seen_calldata(commitment);
        let to_hex = format!("0x{}", hex::encode(self.contract_address));
        let data_hex = format!("0x{}", hex::encode(calldata));

        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_call",
            "params": [{
                "to": to_hex,
                "data": data_hex
            }, "latest"],
            "id": 1
        });

        let resp = self.http.post(&self.rpc_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(StorageError::ServerError {
                status: resp.status().as_u16(),
                message: "eth_call failed".into(),
            });
        }

        let body: serde_json::Value = resp.json().await?;
        if let Some(res_str) = body["result"].as_str() {
            let trimmed = res_str.trim_start_matches("0x");
            if trimmed.is_empty() || trimmed.chars().all(|c| c == '0') {
                return Ok(None);
            }
            let block = u64::from_str_radix(trimmed, 16)
                .map_err(|e| StorageError::ServerError {
                    status: 500,
                    message: format!("Invalid hex block number from contract: {}", e),
                })?;
            if block == 0 {
                Ok(None)
            } else {
                Ok(Some(block))
            }
        } else {
            Ok(None)
        }
    }

    /// Queries transaction receipt via JSON-RPC `eth_getTransactionReceipt`.
    pub async fn get_transaction_receipt(
        &self,
        tx_hash: &[u8; 32],
    ) -> Result<Option<TransactionReceipt>, StorageError> {
        let tx_hex = format!("0x{}", hex::encode(tx_hash));
        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_getTransactionReceipt",
            "params": [tx_hex],
            "id": 1
        });

        let resp = self.http.post(&self.rpc_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(StorageError::ServerError {
                status: resp.status().as_u16(),
                message: "Failed to fetch transaction receipt".into(),
            });
        }

        let body: serde_json::Value = resp.json().await?;
        if body["result"].is_null() {
            return Ok(None);
        }

        let result = &body["result"];
        let block_hex = result["blockNumber"].as_str().unwrap_or("0x0");
        let block_number = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16)
            .unwrap_or(0);

        let status_hex = result["status"].as_str().unwrap_or("0x0");
        let status = status_hex == "0x1" || status_hex == "0x01" || status_hex == "1";

        Ok(Some(TransactionReceipt {
            transaction_hash: *tx_hash,
            block_number,
            status,
        }))
    }

    /// Verifies an off-chain CheckpointEvidence against the commitment math and on-chain contract.
    pub async fn verify_evidence(
        &self,
        evidence: &CheckpointEvidence,
    ) -> Result<AnchorVerificationReport, StorageError> {
        let preimage_valid = evidence.verify_commitment();
        let mut commitment_arr = [0u8; 32];
        if evidence.commitment.len() == 32 {
            commitment_arr.copy_from_slice(&evidence.commitment);
        }

        let current_block = self.get_block_number().await.unwrap_or(evidence.block_number);

        // Query contract for existing registration
        let contract_block = self.query_first_seen_block(&commitment_arr).await.unwrap_or(None);
        let on_chain_confirmed = contract_block.is_some();
        let effective_block = contract_block.unwrap_or(evidence.block_number);

        let finality_stage = if !preimage_valid || !on_chain_confirmed {
            AnchorFinalityStage::Pending
        } else {
            let confirmations = current_block.saturating_sub(effective_block);
            if confirmations >= 50400 {
                AnchorFinalityStage::AssertionSettled {
                    block_number: effective_block,
                }
            } else if confirmations >= 64 {
                AnchorFinalityStage::ParentDataFinalized {
                    block_number: effective_block,
                }
            } else {
                AnchorFinalityStage::SequencerConfirmed {
                    block_number: effective_block,
                }
            }
        };

        Ok(AnchorVerificationReport {
            commitment_hex: hex::encode(&evidence.commitment),
            preimage_valid,
            contract_address_hex: hex::encode(&evidence.contract_address),
            chain_id: evidence.chain_id,
            recorded_block_number: evidence.block_number,
            current_chain_block: current_block,
            finality_stage,
            on_chain_confirmed,
            tx_hash_hex: hex::encode(&evidence.tx_hash),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_selector_computation() {
        let sel_pub = ArbitrumAnchorClient::compute_selector("publish(bytes32)");
        let sel_get = ArbitrumAnchorClient::compute_selector("getFirstSeenBlock(bytes32)");

        assert_eq!(sel_pub.len(), 4);
        assert_eq!(sel_get.len(), 4);
        assert_ne!(sel_pub, sel_get);

        let commitment = [0x55u8; 32];
        let calldata = ArbitrumAnchorClient::encode_publish_calldata(&commitment);
        assert_eq!(calldata.len(), 36);
        assert_eq!(&calldata[0..4], &sel_pub);
        assert_eq!(&calldata[4..36], &commitment);
    }

    #[test]
    fn test_commitment_and_evidence_verification() {
        let salt = [0x11u8; 32];
        let head_cid = [0x22u8; 32];
        let contract = [0x33u8; 20];
        let tx_hash = [0x44u8; 32];

        let evidence = CheckpointEvidence::new(salt, head_cid, 42161, contract, tx_hash, 100, 1600000000);
        assert!(evidence.verify_commitment());

        let mut tampered = evidence.clone();
        tampered.salt[0] ^= 0xFF;
        assert!(!tampered.verify_commitment());
    }
}
