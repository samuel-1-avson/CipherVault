use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::consensus::{ConsensusSigner, ValidatorSet};
use crate::error::ChainError;
use crate::merkle::{hash_leaf, MerkleTree, EMPTY_TREE_ROOT};
use crate::types::{
    AnchorProofResponse, BlockHeader, CipherChainBlock, CommitmentTx, PROTOCOL_VERSION,
};

/// Stored index record for an anchored vault commitment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommitmentRecord {
    pub height: u64,
    pub block_hash: [u8; 32],
    pub tx_index: usize,
    pub timestamp_ms: u64,
    pub vault_id: [u8; 32],
    pub salt: [u8; 32],
    pub head_cid: [u8; 32],
}

/// Sovereign append-only distributed ledger and Merkle state machine.
#[derive(Debug, Clone)]
pub struct SovereignLedger {
    chain_id: String,
    validator_set: ValidatorSet,
    blocks: Vec<CipherChainBlock>,
    cumulative_commitments: Vec<[u8; 32]>,
    commitments_index: HashMap<[u8; 32], CommitmentRecord>,
    cid_to_commitment: HashMap<[u8; 32], [u8; 32]>,
    state_merkle_tree: MerkleTree,
    storage_path: Option<PathBuf>,
}

impl SovereignLedger {
    /// Creates and initializes a new sovereign ledger with a cryptographic genesis block.
    pub fn create_genesis(
        chain_id: &str,
        validator_set: ValidatorSet,
        genesis_signers: &[&ConsensusSigner],
        timestamp_ms: u64,
        storage_path: Option<PathBuf>,
    ) -> Result<Self, ChainError> {
        if genesis_signers.is_empty() {
            return Err(ChainError::InvalidGenesis(
                "At least one genesis signer is required".to_string(),
            ));
        }

        let proposer = genesis_signers[0].public_key();
        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: chain_id.to_string(),
            height: 0,
            prev_block_hash: [0u8; 32],
            state_root: EMPTY_TREE_ROOT,
            tx_root: EMPTY_TREE_ROOT,
            timestamp_ms,
            proposer,
            signatures: Vec::new(),
        };

        // Gather signatures from initial validators
        for signer in genesis_signers {
            if validator_set.contains(&signer.public_key()) {
                header.signatures.push(signer.sign_header(&header));
            }
        }

        validator_set.verify_header_signatures(&header)?;

        let genesis_block = CipherChainBlock {
            header,
            transactions: Vec::new(),
        };

        let ledger = Self {
            chain_id: chain_id.to_string(),
            validator_set,
            blocks: vec![genesis_block.clone()],
            cumulative_commitments: Vec::new(),
            commitments_index: HashMap::new(),
            cid_to_commitment: HashMap::new(),
            state_merkle_tree: MerkleTree::new(Vec::new()),
            storage_path,
        };

        if let Some(ref path) = ledger.storage_path {
            ledger.persist_block(&genesis_block, path)?;
        }

        Ok(ledger)
    }

    /// Loads an existing ledger from a disk directory, re-verifying full cryptographic state.
    pub fn open<P: AsRef<Path>>(
        chain_id: &str,
        validator_set: ValidatorSet,
        storage_dir: P,
    ) -> Result<Self, ChainError> {
        let dir = storage_dir.as_ref();
        if !dir.exists() {
            fs::create_dir_all(dir).map_err(|e| ChainError::Io(e.to_string()))?;
        }

        let blocks_dir = dir.join("blocks");
        if !blocks_dir.exists() {
            return Err(ChainError::Io(format!(
                "Blocks directory not found at {}",
                blocks_dir.display()
            )));
        }

        let mut entries: Vec<PathBuf> = fs::read_dir(&blocks_dir)
            .map_err(|e| ChainError::Io(e.to_string()))?
            .filter_map(|res| res.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|ext| ext == "json"))
            .collect();

        entries.sort();

        if entries.is_empty() {
            return Err(ChainError::BlockNotFound(0));
        }

        let genesis_json =
            fs::read_to_string(&entries[0]).map_err(|e| ChainError::Io(e.to_string()))?;
        let genesis_block: CipherChainBlock = serde_json::from_str(&genesis_json)
            .map_err(|e| ChainError::Serialization(e.to_string()))?;

        if genesis_block.header.height != 0 {
            return Err(ChainError::InvalidHeight {
                expected: 0,
                found: genesis_block.header.height,
            });
        }
        validator_set.verify_header_signatures(&genesis_block.header)?;

        let mut ledger = Self {
            chain_id: chain_id.to_string(),
            validator_set: validator_set.clone(),
            blocks: vec![genesis_block],
            cumulative_commitments: Vec::new(),
            commitments_index: HashMap::new(),
            cid_to_commitment: HashMap::new(),
            state_merkle_tree: MerkleTree::new(Vec::new()),
            storage_path: Some(dir.to_path_buf()),
        };

        for path in entries.into_iter().skip(1) {
            let block_json =
                fs::read_to_string(&path).map_err(|e| ChainError::Io(e.to_string()))?;
            let block: CipherChainBlock = serde_json::from_str(&block_json)
                .map_err(|e| ChainError::Serialization(e.to_string()))?;
            ledger.commit_block_internal(block, false)?;
        }

        Ok(ledger)
    }

    /// Active chain ID string.
    pub fn chain_id(&self) -> &str {
        &self.chain_id
    }

    /// Current height of the ledger (genesis is 0).
    pub fn height(&self) -> u64 {
        self.blocks.last().map(|b| b.header.height).unwrap_or(0)
    }

    /// Latest committed block.
    pub fn latest_block(&self) -> &CipherChainBlock {
        self.blocks.last().expect("Genesis block always present")
    }

    /// Latest cumulative state Merkle root.
    pub fn state_root(&self) -> [u8; 32] {
        self.state_merkle_tree.root()
    }

    /// Validator set authorized on this ledger.
    pub fn validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    /// Proposes a new block packaging pending transactions.
    pub fn propose_block(
        &self,
        proposer: &ConsensusSigner,
        txs: Vec<CommitmentTx>,
        timestamp_ms: u64,
    ) -> Result<CipherChainBlock, ChainError> {
        let proposer_pubkey = proposer.public_key();
        if !self.validator_set.contains(&proposer_pubkey) {
            return Err(ChainError::UnauthorizedValidator(hex::encode(
                proposer_pubkey,
            )));
        }

        let latest = self.latest_block();
        if timestamp_ms <= latest.header.timestamp_ms {
            return Err(ChainError::InvalidTimestamp {
                block: timestamp_ms,
                prev: latest.header.timestamp_ms,
            });
        }

        // Validate all transactions
        for tx in &txs {
            tx.verify_signature(&self.chain_id)?;
        }

        // Compute tx_root
        let tx_leaf_hashes: Vec<[u8; 32]> = txs.iter().map(|tx| tx.tx_leaf_hash()).collect();
        let tx_tree = MerkleTree::new(tx_leaf_hashes);
        let tx_root = tx_tree.root();

        // Compute prospective cumulative state_root
        let mut prospective_commitments = self.cumulative_commitments.clone();
        for tx in &txs {
            prospective_commitments.push(hash_leaf(&tx.commitment));
        }
        let prospective_state_tree = MerkleTree::new(prospective_commitments);
        let state_root = prospective_state_tree.root();

        let mut header = BlockHeader {
            version: PROTOCOL_VERSION,
            chain_id: self.chain_id.clone(),
            height: latest.header.height + 1,
            prev_block_hash: latest.header.block_hash(),
            state_root,
            tx_root,
            timestamp_ms,
            proposer: proposer_pubkey,
            signatures: Vec::new(),
        };

        // Proposer endorses the block as first signer
        header.signatures.push(proposer.sign_header(&header));

        Ok(CipherChainBlock {
            header,
            transactions: txs,
        })
    }

    /// Commits and applies a proposed block after gathering quorum signatures.
    pub fn commit_block(&mut self, block: CipherChainBlock) -> Result<(), ChainError> {
        self.commit_block_internal(block, true)
    }

    fn commit_block_internal(
        &mut self,
        block: CipherChainBlock,
        persist: bool,
    ) -> Result<(), ChainError> {
        let latest = self.latest_block();

        // 1. Verify height sequence
        let expected_height = latest.header.height + 1;
        if block.header.height != expected_height {
            return Err(ChainError::InvalidHeight {
                expected: expected_height,
                found: block.header.height,
            });
        }

        // 2. Verify previous block hash
        let expected_prev_hash = latest.header.block_hash();
        if block.header.prev_block_hash != expected_prev_hash {
            return Err(ChainError::InvalidPrevHash {
                expected: hex::encode(expected_prev_hash),
                found: hex::encode(block.header.prev_block_hash),
            });
        }

        // 3. Verify monotonic timestamp
        if block.header.timestamp_ms <= latest.header.timestamp_ms {
            return Err(ChainError::InvalidTimestamp {
                block: block.header.timestamp_ms,
                prev: latest.header.timestamp_ms,
            });
        }

        // 4. Verify transactions and compute tx_root
        for tx in &block.transactions {
            tx.verify_signature(&self.chain_id)?;
        }
        let tx_leaf_hashes: Vec<[u8; 32]> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_leaf_hash())
            .collect();
        let tx_tree = MerkleTree::new(tx_leaf_hashes);
        if tx_tree.root() != block.header.tx_root {
            return Err(ChainError::InvalidMerkleRoot {
                expected: hex::encode(tx_tree.root()),
                found: hex::encode(block.header.tx_root),
            });
        }

        // 5. Verify prospective cumulative state_root
        let mut prospective_commitments = self.cumulative_commitments.clone();
        for tx in &block.transactions {
            prospective_commitments.push(hash_leaf(&tx.commitment));
        }
        let prospective_state_tree = MerkleTree::new(prospective_commitments.clone());
        if prospective_state_tree.root() != block.header.state_root {
            return Err(ChainError::InvalidStateRoot {
                expected: hex::encode(prospective_state_tree.root()),
                found: hex::encode(block.header.state_root),
            });
        }

        // 6. Verify validator quorum signatures
        self.validator_set.verify_header_signatures(&block.header)?;

        // 7. Persist block if disk backing is enabled
        if persist {
            if let Some(ref path) = self.storage_path.clone() {
                self.persist_block(&block, path)?;
            }
        }

        // 8. Commit state transitions to memory indexes
        let block_hash = block.header.block_hash();
        for (idx, tx) in block.transactions.iter().enumerate() {
            let record = CommitmentRecord {
                height: block.header.height,
                block_hash,
                tx_index: idx,
                timestamp_ms: block.header.timestamp_ms,
                vault_id: tx.vault_id,
                salt: tx.salt,
                head_cid: tx.head_cid,
            };
            self.commitments_index.insert(tx.commitment, record);
            self.cid_to_commitment.insert(tx.head_cid, tx.commitment);
        }

        self.cumulative_commitments = prospective_commitments;
        self.state_merkle_tree = prospective_state_tree;
        self.blocks.push(block);

        Ok(())
    }

    fn persist_block(&self, block: &CipherChainBlock, base_dir: &Path) -> Result<(), ChainError> {
        let blocks_dir = base_dir.join("blocks");
        if !blocks_dir.exists() {
            fs::create_dir_all(&blocks_dir).map_err(|e| ChainError::Io(e.to_string()))?;
        }
        let file_path = blocks_dir.join(format!("{:012}.json", block.header.height));
        let serialized = serde_json::to_string_pretty(block)
            .map_err(|e| ChainError::Serialization(e.to_string()))?;
        fs::write(file_path, serialized).map_err(|e| ChainError::Io(e.to_string()))?;
        Ok(())
    }

    /// Queries cryptographic inclusion proof for an anchored commitment.
    pub fn get_proof_for_commitment(
        &self,
        commitment: &[u8; 32],
    ) -> Result<AnchorProofResponse, ChainError> {
        let record = self
            .commitments_index
            .get(commitment)
            .ok_or_else(|| ChainError::CommitmentNotFound(hex::encode(commitment)))?;

        let block = self
            .blocks
            .iter()
            .find(|b| b.header.height == record.height)
            .ok_or(ChainError::BlockNotFound(record.height))?;

        let tx_leaf_hashes: Vec<[u8; 32]> = block
            .transactions
            .iter()
            .map(|tx| tx.tx_leaf_hash())
            .collect();
        let tx_tree = MerkleTree::new(tx_leaf_hashes);

        let tx_proof = tx_tree
            .generate_proof(record.tx_index)
            .ok_or_else(|| ChainError::InvalidInclusionProof("Proof generation failed".into()))?;

        Ok(AnchorProofResponse {
            chain_id: self.chain_id.clone(),
            height: record.height,
            block_hash: record.block_hash,
            timestamp_ms: record.timestamp_ms,
            commitment: *commitment,
            head_cid: record.head_cid,
            salt: record.salt,
            tx_index: record.tx_index,
            tx_proof,
            header: block.header.clone(),
            validator_signatures_count: block.header.signatures.len(),
        })
    }

    /// Queries cryptographic inclusion proof by vault snapshot head CID.
    pub fn get_proof_for_head_cid(
        &self,
        head_cid: &[u8; 32],
    ) -> Result<AnchorProofResponse, ChainError> {
        let commitment = self
            .cid_to_commitment
            .get(head_cid)
            .ok_or_else(|| ChainError::CommitmentNotFound(hex::encode(head_cid)))?;
        self.get_proof_for_commitment(commitment)
    }
}
