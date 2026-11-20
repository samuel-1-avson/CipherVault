//! Read-only projection of the local ledger for Explorer surfaces.

use anyhow::{bail, Context, Result};
use ciphervault_chain::{ChainError, CipherChainBlock, SovereignLedger, SOVEREIGN_CHAIN_ID_STR};

#[derive(Clone, serde::Serialize)]
pub(crate) struct ExplorerBlock {
    pub height: u64,
    pub hash: String,
    pub timestamp_ms: u64,
    pub timestamp_signed: bool,
    pub signatures: usize,
    pub commitments: usize,
}

impl From<&CipherChainBlock> for ExplorerBlock {
    fn from(block: &CipherChainBlock) -> Self {
        Self {
            height: block.header.height,
            hash: hex::encode(block.header.block_hash()),
            timestamp_ms: block.header.timestamp_ms,
            timestamp_signed: block.header.timestamp_is_signed(),
            signatures: block.header.signatures.len(),
            commitments: block.transactions.len(),
        }
    }
}

#[derive(serde::Serialize)]
pub(crate) struct ExplorerBlockDetail {
    pub block: ExplorerBlock,
    pub parent_hash: String,
    pub transaction_root: String,
    pub signers: Vec<String>,
    pub commitments: Vec<String>,
    pub inclusion: Option<ExplorerInclusion>,
}

#[derive(serde::Serialize)]
pub(crate) struct ExplorerInclusion {
    pub commitment: String,
    pub index: usize,
    pub proof_steps: usize,
}

#[derive(serde::Serialize)]
pub(crate) struct ChainExplorer {
    pub state: &'static str,
    pub chain_id: &'static str,
    pub solo: bool,
    pub blocks: Vec<ExplorerBlock>,
    pub detail: Option<ExplorerBlockDetail>,
}

enum BlockQuery {
    Height(u64),
    Digest([u8; 32]),
}

fn parse_query(raw: &str) -> Result<BlockQuery> {
    let raw = raw.trim();
    let digest = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    if digest.len() == 64 {
        let mut bytes = [0; 32];
        hex::decode_to_slice(digest, &mut bytes).context("Invalid block hash or commitment")?;
        return Ok(BlockQuery::Digest(bytes));
    }
    let height = raw.trim_start_matches('#');
    if !height.is_empty() && height.bytes().all(|value| value.is_ascii_digit()) {
        return Ok(BlockQuery::Height(
            height.parse().context("Invalid block height")?,
        ));
    }
    bail!("Enter a block height, 64-character block hash, or opaque commitment");
}

pub(crate) fn read_chain_explorer(query: Option<&str>) -> Result<ChainExplorer> {
    read_chain_explorer_at(&crate::util::get_vault_directory().join("chain"), query)
}

pub(crate) fn read_chain_explorer_at(
    chain_dir: &std::path::Path,
    query: Option<&str>,
) -> Result<ChainExplorer> {
    let query = query.map(parse_query).transpose()?;
    let mut view = ChainExplorer {
        state: "empty",
        chain_id: SOVEREIGN_CHAIN_ID_STR,
        solo: false,
        blocks: Vec::new(),
        detail: None,
    };
    if !chain_dir.join("blocks").is_dir() {
        return Ok(view);
    }
    let genesis = match SovereignLedger::read_genesis_validators(chain_dir)? {
        Some(set) => set,
        None => super::anchor::read_configured_validator_set(chain_dir)?
            .context("The local ledger has no saved validator set")?,
    };
    let ledger = SovereignLedger::open(SOVEREIGN_CHAIN_ID_STR, genesis.clone(), chain_dir)
        .context("The local CipherChain ledger could not be verified")?;
    view.state = "ready";
    view.solo = genesis.len() == 1
        && ledger.validator_set().len() == 1
        && ledger.blocks().iter().all(|block| {
            block
                .header
                .next_validators
                .as_ref()
                .is_none_or(|keys| keys.len() == 1)
        });
    view.blocks = ledger
        .blocks()
        .iter()
        .rev()
        .take(20)
        .map(ExplorerBlock::from)
        .collect();
    if let Some(query) = query {
        let mut inclusion = None;
        let block = match query {
            BlockQuery::Height(height) => ledger.block_at_height(height),
            BlockQuery::Digest(digest) => {
                let block = ledger
                    .blocks()
                    .iter()
                    .find(|block| block.header.block_hash() == digest);
                if block.is_some() {
                    block
                } else {
                    match ledger.get_proof_for_commitment(&digest) {
                        Ok(proof) => {
                            let tx = proof.tx.as_ref().context("Missing committed transaction")?;
                            anyhow::ensure!(
                                tx.commitment == digest
                                    && proof.tx_index == proof.tx_proof.leaf_index
                                    && tx.tx_leaf_hash() == proof.tx_proof.leaf_hash
                                    && proof.tx_proof.verify_bound(&proof.header.tx_root),
                                "The local commitment proof did not verify"
                            );
                            inclusion = Some(ExplorerInclusion {
                                commitment: hex::encode(digest),
                                index: proof.tx_index,
                                proof_steps: proof.tx_proof.steps.len(),
                            });
                            ledger.block_at_height(proof.height)
                        }
                        Err(ChainError::CommitmentNotFound(_)) => None,
                        Err(error) => return Err(error.into()),
                    }
                }
            }
        };
        if let Some(block) = block {
            view.detail = Some(ExplorerBlockDetail {
                block: ExplorerBlock::from(block),
                parent_hash: hex::encode(block.header.prev_block_hash),
                transaction_root: hex::encode(block.header.tx_root),
                signers: block
                    .header
                    .signatures
                    .iter()
                    .take(64)
                    .map(|sig| hex::encode(sig.validator))
                    .collect(),
                commitments: block
                    .transactions
                    .iter()
                    .take(64)
                    .map(|tx| hex::encode(tx.commitment))
                    .collect(),
                inclusion,
            });
        } else {
            view.state = "not_found";
        }
    }
    Ok(view)
}
