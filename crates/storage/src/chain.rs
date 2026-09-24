use reqwest::Client;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha3::{Digest, Keccak256};
use std::time::Duration;

use crate::error::StorageError;
use ciphervault_format::CheckpointEvidence;

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
    /// True only when an independent RPC receipt exists, succeeded, and the
    /// commitment is present in the registry contract. The receipt block and
    /// the registry first-seen block are NOT compared: on Arbitrum the former
    /// is an L2 block number while `block.number` in-contract is L1-derived.
    #[serde(default)]
    pub receipt_verified: bool,
    #[serde(default)]
    pub receipt_block_number: Option<u64>,
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

        let block = u64::from_str_radix(hex_str.trim_start_matches("0x"), 16).map_err(|e| {
            StorageError::ServerError {
                status: 500,
                message: format!("Invalid hex block number: {}", e),
            }
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
            let block =
                u64::from_str_radix(trimmed, 16).map_err(|e| StorageError::ServerError {
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
        let block_number = u64::from_str_radix(block_hex.trim_start_matches("0x"), 16).unwrap_or(0);

        let status_hex = result["status"].as_str().unwrap_or("0x0");
        let status = status_hex == "0x1" || status_hex == "0x01" || status_hex == "1";

        Ok(Some(TransactionReceipt {
            transaction_hash: *tx_hash,
            block_number,
            status,
        }))
    }

    /// Submits a signed raw Ethereum transaction via JSON-RPC `eth_sendRawTransaction`.
    /// Returns the 32-byte transaction hash.
    pub async fn send_raw_transaction(&self, raw_tx_hex: &str) -> Result<[u8; 32], StorageError> {
        let formatted_hex = if raw_tx_hex.starts_with("0x") {
            raw_tx_hex.to_string()
        } else {
            format!("0x{}", raw_tx_hex)
        };

        let payload = json!({
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [formatted_hex],
            "id": 1
        });

        let resp = self.http.post(&self.rpc_url).json(&payload).send().await?;
        if !resp.status().is_success() {
            return Err(StorageError::ServerError {
                status: resp.status().as_u16(),
                message: "eth_sendRawTransaction HTTP request failed".into(),
            });
        }

        let body: serde_json::Value = resp.json().await?;
        if let Some(err) = body.get("error") {
            let msg = err["message"].as_str().unwrap_or("Unknown RPC error");
            return Err(StorageError::ServerError {
                status: 400,
                message: format!("eth_sendRawTransaction failed: {}", msg),
            });
        }

        let tx_hash_str = body["result"]
            .as_str()
            .ok_or_else(|| StorageError::ServerError {
                status: 500,
                message: "Missing result in eth_sendRawTransaction response".into(),
            })?;

        let clean_hex = tx_hash_str.trim_start_matches("0x");
        let hash_bytes = hex::decode(clean_hex).map_err(|e| StorageError::ServerError {
            status: 500,
            message: format!("Invalid hex in transaction hash: {}", e),
        })?;

        if hash_bytes.len() != 32 {
            return Err(StorageError::ServerError {
                status: 500,
                message: format!(
                    "Invalid transaction hash length: expected 32 bytes, got {}",
                    hash_bytes.len()
                ),
            });
        }

        let mut tx_hash = [0u8; 32];
        tx_hash.copy_from_slice(&hash_bytes);
        Ok(tx_hash)
    }

    /// Polls `eth_getTransactionReceipt` until the transaction is mined or timeout expires.
    pub async fn wait_for_receipt(
        &self,
        tx_hash: &[u8; 32],
        max_wait: Duration,
        interval: Duration,
    ) -> Result<TransactionReceipt, StorageError> {
        let start = std::time::Instant::now();
        loop {
            if let Some(receipt) = self.get_transaction_receipt(tx_hash).await? {
                return Ok(receipt);
            }

            if start.elapsed() >= max_wait {
                return Err(StorageError::ServerError {
                    status: 408,
                    message: format!(
                        "Timed out waiting for transaction receipt for 0x{}",
                        hex::encode(tx_hash)
                    ),
                });
            }

            tokio::time::sleep(interval).await;
        }
    }

    /// Verifies an off-chain CheckpointEvidence against the commitment math and on-chain contract.
    pub async fn verify_evidence(
        &self,
        evidence: &CheckpointEvidence,
    ) -> Result<AnchorVerificationReport, StorageError> {
        if evidence.chain_id != self.chain_id {
            return Err(StorageError::ServerError {
                status: 400,
                message: format!(
                    "Checkpoint chain id {} does not match configured chain {}",
                    evidence.chain_id, self.chain_id
                ),
            });
        }
        if evidence.contract_address.len() != 20
            || evidence.contract_address.as_slice() != self.contract_address.as_slice()
        {
            return Err(StorageError::ServerError {
                status: 400,
                message: "Checkpoint contract address does not match the configured registry"
                    .into(),
            });
        }
        let preimage_valid = evidence.verify_commitment();
        let mut commitment_arr = [0u8; 32];
        if evidence.commitment.len() == 32 {
            commitment_arr.copy_from_slice(&evidence.commitment);
        }

        let current_block = self
            .get_block_number()
            .await
            .unwrap_or(evidence.block_number);

        // Query contract for existing registration.
        let contract_block = self
            .query_first_seen_block(&commitment_arr)
            .await
            .unwrap_or(None);

        // A relayer-supplied block/tx pair is not evidence by itself. When a
        // transaction hash is present, independently query the chain receipt
        // and require a successful receipt plus registry inclusion of this
        // exact commitment. Pre-submission evidence (all-zero tx hash) can
        // still be observed in the registry, but it is not receipt-backed.
        let tx_hash_present =
            evidence.tx_hash.len() == 32 && evidence.tx_hash.iter().any(|byte| *byte != 0);
        let receipt = if tx_hash_present {
            let mut tx_hash = [0u8; 32];
            tx_hash.copy_from_slice(&evidence.tx_hash);
            self.get_transaction_receipt(&tx_hash).await.ok().flatten()
        } else {
            None
        };
        let (receipt_verified, on_chain_confirmed, finality_stage) = evaluate_anchor_confirmation(
            preimage_valid,
            tx_hash_present,
            receipt.as_ref(),
            contract_block,
            current_block,
        );
        let receipt_block_number = receipt.as_ref().map(|receipt| receipt.block_number);

        Ok(AnchorVerificationReport {
            commitment_hex: hex::encode(&evidence.commitment),
            preimage_valid,
            contract_address_hex: hex::encode(&evidence.contract_address),
            chain_id: evidence.chain_id,
            recorded_block_number: evidence.block_number,
            current_chain_block: current_block,
            finality_stage,
            on_chain_confirmed,
            receipt_verified,
            receipt_block_number,
            tx_hash_hex: hex::encode(&evidence.tx_hash),
        })
    }
}

/// Pure evaluation of anchor confirmation from chain observations.
///
/// `contract_block` is the registry first-seen block for the commitment and
/// `current_block` is the head from `eth_blockNumber`. On Arbitrum these live
/// in different domains: `block.number` in-contract is L1-derived while
/// receipts and `eth_blockNumber` are L2, so they must never be equated or
/// subtracted across domains. Confirmation counting therefore uses the
/// receipt's L2 block against the L2 head; the registry value is an
/// inclusion-only signal.
pub fn evaluate_anchor_confirmation(
    preimage_valid: bool,
    tx_hash_present: bool,
    receipt: Option<&TransactionReceipt>,
    contract_block: Option<u64>,
    current_block: u64,
) -> (bool, bool, AnchorFinalityStage) {
    let receipt_ok = matches!(receipt, Some(receipt) if receipt.status);
    let receipt_verified = tx_hash_present && receipt_ok && contract_block.is_some();
    let on_chain_confirmed = contract_block.is_some() && receipt_verified;
    if !preimage_valid || !on_chain_confirmed {
        return (
            receipt_verified,
            on_chain_confirmed,
            AnchorFinalityStage::Pending,
        );
    }
    let effective_block = receipt
        .map(|receipt| receipt.block_number)
        .unwrap_or(current_block);
    let confirmations = current_block.saturating_sub(effective_block);
    let finality_stage = if confirmations >= 50400 {
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
    };
    (receipt_verified, on_chain_confirmed, finality_stage)
}

/// Receipt returned by an automated L2 relayer service.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayerReceipt {
    pub commitment_hex: String,
    pub tx_hash_hex: String,
    pub block_number: u64,
    pub status: String,
    pub timestamp: u64,
}

/// Client for interacting with an automated L2 checkpoint relayer service.
#[derive(Clone)]
pub struct AnchorRelayerClient {
    relayer_url: String,
    http: Client,
}

impl AnchorRelayerClient {
    pub fn new(relayer_url: String) -> Self {
        let http = Client::builder()
            .timeout(Duration::from_secs(15))
            .build()
            .unwrap_or_else(|_| Client::new());
        Self {
            relayer_url: relayer_url.trim_end_matches('/').to_string(),
            http,
        }
    }

    pub fn relayer_url(&self) -> &str {
        &self.relayer_url
    }

    fn with_service_token(&self, request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
            Ok(token) if !token.is_empty() => request.header("X-CipherVault-Service-Token", token),
            _ => request,
        }
    }

    /// Submits a signed checkpoint evidence to the relayer for automated L2 anchoring.
    pub async fn submit_checkpoint(
        &self,
        evidence: &CheckpointEvidence,
    ) -> Result<RelayerReceipt, StorageError> {
        let url = format!("{}/v1/relayer/checkpoints", self.relayer_url);
        let resp = self
            .with_service_token(self.http.post(&url))
            .json(evidence)
            .send()
            .await?;
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError {
                status,
                message: format!("Relayer error: {}", body),
            });
        }
        let receipt: RelayerReceipt = resp.json().await?;
        Ok(receipt)
    }

    /// Queries the relayer for status of a specific commitment.
    pub async fn get_checkpoint(
        &self,
        commitment: &[u8; 32],
    ) -> Result<Option<RelayerReceipt>, StorageError> {
        let commitment_hex = hex::encode(commitment);
        let url = format!(
            "{}/v1/relayer/checkpoints/{}",
            self.relayer_url, commitment_hex
        );
        let resp = self.with_service_token(self.http.get(&url)).send().await?;
        if resp.status().as_u16() == 404 {
            return Ok(None);
        }
        if !resp.status().is_success() {
            let status = resp.status().as_u16();
            let body = resp.text().await.unwrap_or_default();
            return Err(StorageError::ServerError {
                status,
                message: format!("Relayer error: {}", body),
            });
        }
        let receipt: RelayerReceipt = resp.json().await?;
        Ok(Some(receipt))
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
        // Pinned against an independent implementation (Python
        // pycryptodome keccak): guards the Rust encoder against drift
        // from the canonical selectors. The forge-side mirror lives in
        // contracts/test/RustCalldata.t.sol.
        assert_eq!(sel_pub, [0x8b, 0x2e, 0x6d, 0xcf]);
        assert_eq!(sel_get, [0x21, 0x0e, 0x19, 0xc3]);

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

        let evidence =
            CheckpointEvidence::new(salt, head_cid, 42161, contract, tx_hash, 100, 1600000000);
        assert!(evidence.verify_commitment());

        let mut tampered = evidence.clone();
        tampered.salt[0] ^= 0xFF;
        assert!(!tampered.verify_commitment());
    }

    fn receipt_at(block_number: u64) -> TransactionReceipt {
        TransactionReceipt {
            transaction_hash: [0x44u8; 32],
            block_number,
            status: true,
        }
    }

    #[test]
    fn test_confirms_when_l1_registry_block_differs_from_l2_receipt() {
        // Live Arbitrum Sepolia case: registry `block.number` is L1-derived
        // (11770313) while the receipt and head are L2 (312389514/312389711).
        let receipt = receipt_at(312_389_514);
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(true, true, Some(&receipt), Some(11_770_313), 312_389_550);
        assert!(verified);
        assert!(confirmed);
        assert_eq!(
            stage,
            AnchorFinalityStage::SequencerConfirmed {
                block_number: 312_389_514
            }
        );
    }

    #[test]
    fn test_pending_without_registry_inclusion() {
        let receipt = receipt_at(100);
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(true, true, Some(&receipt), None, 150);
        assert!(!verified);
        assert!(!confirmed);
        assert_eq!(stage, AnchorFinalityStage::Pending);
    }

    #[test]
    fn test_pending_on_failed_receipt() {
        let receipt = TransactionReceipt {
            transaction_hash: [0x44u8; 32],
            block_number: 100,
            status: false,
        };
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(true, true, Some(&receipt), Some(90), 150);
        assert!(!verified);
        assert!(!confirmed);
        assert_eq!(stage, AnchorFinalityStage::Pending);
    }

    #[test]
    fn test_pending_for_presubmission_evidence() {
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(true, false, None, Some(90), 150);
        assert!(!verified);
        assert!(!confirmed);
        assert_eq!(stage, AnchorFinalityStage::Pending);
    }

    #[test]
    fn test_advances_finality_with_l2_confirmations() {
        let receipt = receipt_at(1000);
        let (_, _, stage) =
            evaluate_anchor_confirmation(true, true, Some(&receipt), Some(50), 1064);
        assert_eq!(
            stage,
            AnchorFinalityStage::ParentDataFinalized { block_number: 1000 }
        );
        let (_, _, stage) =
            evaluate_anchor_confirmation(true, true, Some(&receipt), Some(50), 51400);
        assert_eq!(
            stage,
            AnchorFinalityStage::AssertionSettled { block_number: 1000 }
        );
    }

    #[test]
    fn test_pending_on_bad_preimage_despite_chain_proof() {
        let receipt = receipt_at(100);
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(true, false, Some(&receipt), Some(90), 150);
        assert!(!verified);
        assert!(!confirmed);
        assert_eq!(stage, AnchorFinalityStage::Pending);
        let (verified, confirmed, stage) =
            evaluate_anchor_confirmation(false, true, Some(&receipt), Some(90), 150);
        assert!(verified);
        assert!(confirmed);
        assert_eq!(stage, AnchorFinalityStage::Pending);
    }
}
