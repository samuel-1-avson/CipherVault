//! Chain-anchor and anchor-verification commands.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use rand::RngCore;
use std::time::Duration;

use crate::util::get_vault_store;

#[allow(
    clippy::too_many_arguments,
    reason = "Command line parameter forwarding"
)]
pub(crate) async fn cmd_anchor(
    head_hex_opt: Option<String>,
    rpc_opt: Option<String>,
    contract_opt: Option<String>,
    chain_id_opt: Option<u64>,
    tx_hash_opt: Option<String>,
    raw_tx_opt: Option<String>,
    auto_relay: bool,
    relayer_url_opt: Option<String>,
) -> Result<()> {
    let store = get_vault_store()?;
    let active_head = match head_hex_opt {
        Some(h) => {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))?;
            if bytes.len() != 32 {
                bail!("Head CID must be 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to anchor")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    let rpc_url = rpc_opt
        .or_else(|| std::env::var("ARBITRUM_RPC_URL").ok())
        .unwrap_or_else(|| "https://arb1.arbitrum.io/rpc".to_string());

    let chain_id = chain_id_opt
        .or_else(|| {
            std::env::var("ARBITRUM_CHAIN_ID")
                .ok()
                .and_then(|v| v.parse().ok())
        })
        .unwrap_or(42161);

    let contract_str = contract_opt
        .or_else(|| std::env::var("CIPHERVAULT_REGISTRY_CONTRACT").ok())
        .or_else(|| std::env::var("ARBITRUM_CONTRACT_ADDRESS").ok())
        .unwrap_or_else(|| "0x0000000000000000000000000000000000000000".to_string());

    let contract_bytes = {
        let bytes = hex::decode(contract_str.trim().trim_start_matches("0x"))?;
        if bytes.len() != 20 {
            bail!("Contract address must be 20 bytes (40 hex characters)");
        }
        let mut arr = [0u8; 20];
        arr.copy_from_slice(&bytes);
        arr
    };

    println!("{}", "Preparing Arbitrum Checkpoint Commitment...".bold());
    println!("  Head Record CID:   {}", hex::encode(active_head).yellow());
    println!("  Target Chain ID:   {} (Arbitrum)", chain_id);
    println!(
        "  Contract Registry: 0x{}",
        hex::encode(contract_bytes).cyan()
    );

    // Check if we already have pending or recorded checkpoint evidence for active_head!
    let (salt, commitment) = if let Ok(Some(existing)) = store.get_checkpoint_evidence(&active_head)
    {
        let mut s = [0u8; 32];
        let mut c = [0u8; 32];
        if existing.salt.len() == 32 && existing.commitment.len() == 32 {
            s.copy_from_slice(&existing.salt);
            c.copy_from_slice(&existing.commitment);
            println!("  Reusing Pending Commitment: {}", hex::encode(c).green());
            (s, c)
        } else {
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
            (s, c)
        }
    } else {
        let mut s = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut s);
        let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
        (s, c)
    };

    let calldata =
        ciphervault_storage::chain::ArbitrumAnchorClient::encode_publish_calldata(&commitment);

    println!("  Preimage Salt:     {}", hex::encode(salt).dimmed());
    println!(
        "  Opaque Commitment: {}",
        hex::encode(commitment).green().bold()
    );
    println!("  Publish Calldata:  0x{}", hex::encode(&calldata).dimmed());

    let client =
        ciphervault_storage::ArbitrumAnchorClient::new(rpc_url.clone(), chain_id, contract_bytes);

    let current_chain_block = if auto_relay || relayer_url_opt.is_some() {
        0
    } else {
        client.get_block_number().await.context(format!(
            "Failed to query current block from Arbitrum RPC at '{}'. Please check network connectivity or provide a valid RPC endpoint.",
            rpc_url
        ))?
    };

    let (block_num, tx_hash, finality_msg) = if let Some(raw_tx) = raw_tx_opt {
        println!(
            "Broadcasting raw signed transaction to Arbitrum RPC via eth_sendRawTransaction..."
        );
        let th = client
            .send_raw_transaction(&raw_tx)
            .await
            .context("Failed to broadcast raw transaction via eth_sendRawTransaction")?;
        println!(
            "  ✓ Transaction broadcast to L2 sequencer: 0x{}",
            hex::encode(th).cyan()
        );
        println!("Waiting for sequencer transaction receipt confirmation...");
        let rcpt = client
            .wait_for_receipt(&th, Duration::from_secs(30), Duration::from_millis(500))
            .await
            .context("Timed out waiting for L2 sequencer transaction receipt")
            .and_then(|rcpt| {
                // Bind successful receipts to this anchor (same bar as --tx-hash).
                if rcpt.status
                    && contract_bytes != [0u8; 20]
                    && !ciphervault_storage::chain::receipt_binds_commitment(
                        &rcpt,
                        &contract_bytes,
                        &commitment,
                    )
                {
                    Err(anyhow::anyhow!(
                        "Transaction 0x{} succeeded, but it did not publish commitment 0x{} to registry 0x{} (no matching CommitmentPublished log).",
                        hex::encode(th),
                        hex::encode(commitment),
                        hex::encode(contract_bytes)
                    ))
                } else {
                    Ok(rcpt)
                }
            })?;

        if !rcpt.status {
            bail!(
                "Transaction 0x{} failed/reverted on-chain.",
                hex::encode(th)
            );
        }
        println!(
            "{}",
            "✓ Real on-chain transaction receipt verified!"
                .green()
                .bold()
        );

        if contract_bytes != [0u8; 20] {
            let contract_block = client
                .query_first_seen_block(&commitment)
                .await
                .unwrap_or(None);
            if contract_block.is_none() {
                bail!(
                    "Transaction 0x{} succeeded, but commitment 0x{} has not been published to registry contract 0x{}.",
                    hex::encode(th),
                    hex::encode(commitment),
                    hex::encode(contract_bytes)
                );
            }
            println!(
                "{}",
                "✓ Verified exact commitment inclusion in registry contract!"
                    .green()
                    .bold()
            );
        }

        (
            rcpt.block_number,
            th,
            "SequencerConfirmed (Live Arbitrum L2 Receipt)",
        )
    } else if auto_relay || relayer_url_opt.is_some() {
        let relayer_endpoint = relayer_url_opt
            .or_else(|| std::env::var("CIPHERVAULT_RELAYER_URL").ok())
            .unwrap_or_else(|| "http://127.0.0.1:8787".to_string());

        println!(
            "Submitting commitment to automated L2 relayer at {}...",
            relayer_endpoint.cyan()
        );
        let relayer_client = ciphervault_storage::AnchorRelayerClient::new(relayer_endpoint);

        let draft_evidence = ciphervault_format::CheckpointEvidence::new(
            salt,
            active_head,
            chain_id,
            contract_bytes,
            [0u8; 32],
            0,
            Utc::now().timestamp() as u64,
        );

        let receipt = relayer_client
            .submit_checkpoint(&draft_evidence)
            .await
            .context("Failed to submit checkpoint to automated L2 relayer")?;

        let tx_bytes =
            hex::decode(receipt.tx_hash_hex.trim_start_matches("0x")).unwrap_or_default();
        let mut th = [0u8; 32];
        if tx_bytes.len() == 32 {
            th.copy_from_slice(&tx_bytes);
        }

        // Never trust the relayer's word alone: a claimed confirmation is
        // accepted only with a bound receipt plus registry inclusion.
        let included = contract_bytes == [0u8; 20]
            || matches!(
                client.query_first_seen_block(&commitment).await,
                Ok(Some(_))
            );
        let relay_confirmed = receipt.status == "SequencerConfirmed"
            && tx_bytes.len() == 32
            && matches!(
                client.get_transaction_receipt(&th).await,
                Ok(Some(rcpt)) if rcpt.status
                    && (contract_bytes == [0u8; 20]
                        || ciphervault_storage::chain::receipt_binds_commitment(
                            &rcpt, &contract_bytes, &commitment
                        ))
                    && included
            );
        let (block_number, finality_msg) = if relay_confirmed {
            println!(
                "{}",
                "✓ Automated L2 Relayer Sequencer Confirmation Received (independently verified)!"
                    .green()
                    .bold()
            );
            println!("  Relayer Sequencer Tx: 0x{}", receipt.tx_hash_hex.cyan());
            println!("  Sequencer Block:      {}", receipt.block_number);
            println!("  Finality Status:      {}", receipt.status.green());
            (
                receipt.block_number,
                "SequencerConfirmed (Automated L2 Relayer, receipt independently verified)",
            )
        } else {
            if receipt.status == "SequencerConfirmed" {
                println!(
                    "{}",
                    "⚠ Relayer claimed SequencerConfirmed but the on-chain receipt is missing, unbound, or unpublished; treating as queued."
                        .red()
                        .bold()
                );
            }
            println!(
                "{}",
                "✓ Checkpoint queued with automated L2 relayer (pending on-chain sequencer mining)!"
                    .yellow()
                    .bold()
            );
            println!("  Relayer Status:       {}", receipt.status.yellow());
            (0, "QueuedForRelay (Pending L2 Submission)")
        };

        (block_number, th, finality_msg)
    } else if let Some(tx_hex) = tx_hash_opt {
        let tx_clean = tx_hex.trim().trim_start_matches("0x");
        let tx_bytes = hex::decode(tx_clean)?;
        if tx_bytes.len() != 32 {
            bail!("Transaction hash must be 32 bytes (64 hex characters)");
        }
        let mut th = [0u8; 32];
        th.copy_from_slice(&tx_bytes);

        println!(
            "Verifying on-chain transaction receipt for 0x{}...",
            hex::encode(th)
        );
        let rcpt = match client.get_transaction_receipt(&th).await? {
            Some(rcpt) => {
                if !rcpt.status {
                    bail!(
                        "Transaction 0x{} failed/reverted on-chain.",
                        hex::encode(th)
                    );
                }
                println!(
                    "{}",
                    "✓ Real on-chain transaction receipt verified!"
                        .green()
                        .bold()
                );
                rcpt
            }
            None => {
                bail!(
                    "Transaction 0x{} has not been mined yet on Arbitrum chain (receipt is null).",
                    hex::encode(th)
                );
            }
        };

        // Bind the receipt to this anchor: the transaction must have called
        // the registry and emitted its publication event for this commitment.
        // A successful but unrelated transaction (plus an older registry
        // entry) proves nothing about this anchor.
        if contract_bytes != [0u8; 20]
            && !ciphervault_storage::chain::receipt_binds_commitment(
                &rcpt,
                &contract_bytes,
                &commitment,
            )
        {
            bail!(
                "Transaction 0x{} succeeded, but it did not publish commitment 0x{} to registry 0x{} (no matching CommitmentPublished log).",
                hex::encode(th),
                hex::encode(commitment),
                hex::encode(contract_bytes)
            );
        }

        // Strict verification: Verify that this EXACT commitment was actually registered in the registry contract
        if contract_bytes != [0u8; 20] {
            let contract_block = client
                .query_first_seen_block(&commitment)
                .await
                .unwrap_or(None);
            if contract_block.is_none() {
                bail!(
                    "Transaction 0x{} succeeded, but commitment 0x{} has not been published to registry contract 0x{}. The transaction must call publish(bytes32) with this exact commitment.",
                    hex::encode(th),
                    hex::encode(commitment),
                    hex::encode(contract_bytes)
                );
            }
            println!(
                "{}",
                "✓ Verified exact commitment inclusion in registry contract!"
                    .green()
                    .bold()
            );
        }

        (
            rcpt.block_number,
            th,
            "SequencerConfirmed (Verified On-Chain Contract Inclusion)",
        )
    } else {
        // Query contract if already published
        let contract_block = if contract_bytes != [0u8; 20] {
            client
                .query_first_seen_block(&commitment)
                .await
                .unwrap_or(None)
        } else {
            None
        };

        if let Some(first_block) = contract_block {
            println!(
                "{}",
                "✓ Commitment already verified on-chain in registry contract!"
                    .green()
                    .bold()
            );
            (
                first_block,
                [0u8; 32],
                "Contract Confirmed (Historical Block)",
            )
        } else {
            println!("\n{}", "To anchor this commitment on Arbitrum, execute the transaction via cast or wallet:".cyan().bold());
            println!("  cast send 0x{} \"publish(bytes32)\" 0x{} --rpc-url {} --private-key $PRIVATE_KEY\n",
                hex::encode(contract_bytes),
                hex::encode(commitment),
                rpc_url
            );
            println!("Once broadcast, record the live receipt with: ciphervault anchor --tx-hash <TX_HASH>\n");
            (
                current_chain_block,
                [0u8; 32],
                "Commitment Proof Persisted (Awaiting Transaction Broadcast)",
            )
        }
    };

    let evidence = ciphervault_format::CheckpointEvidence::new(
        salt,
        active_head,
        chain_id,
        contract_bytes,
        tx_hash,
        block_num,
        Utc::now().timestamp() as u64,
    );

    store.save_checkpoint_evidence(&evidence)?;

    println!(
        "{}",
        "✓ Checkpoint commitment recorded in local vault!"
            .bold()
            .green()
    );
    println!("  Block Number:      {}", block_num);
    if tx_hash != [0u8; 32] {
        println!("  Tx Hash:           0x{}", hex::encode(tx_hash).dimmed());
    } else {
        println!("  Tx Hash:           None (Self-sovereign commitment proof generated)");
    }
    println!("  Finality Status:   {}", finality_msg.green());
    println!("Off-chain salt and cryptographic evidence persisted in vault database.");

    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::items_after_test_module,
    reason = "record-path binding tests live beside cmd_anchor; cmd_verify_anchor follows"
)]
mod tests {
    use super::*;
    use axum::routing::post;
    use axum::{Json, Router};
    use ciphervault_format::CheckpointEvidence;
    use ciphervault_local_store::LocalVaultStore;
    use ciphervault_storage::chain::COMMITMENT_PUBLISHED_TOPIC;
    use serde_json::{json, Value};
    use tokio::net::TcpListener;

    /// Fixed fixtures shared by both tests so the global vault-path override
    /// cannot skew results if tests interleave: only the mock receipt differs.
    const SALT: [u8; 32] = [0x11u8; 32];
    const HEAD: [u8; 32] = [0x22u8; 32];
    const REGISTRY: [u8; 20] = [0x55u8; 20];
    const TX_HASH_HEX: &str = "0x9876543210987654321098765432109876543210987654321098765432109876";

    /// Serializes vault-path override tests: `set_active_vault_path` is
    /// process-global, so interleaved tests would otherwise write into
    /// each other's temp vaults.
    static VAULT_PATH_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    struct Fixture {
        dir: std::path::PathBuf,
        rpc_url: String,
    }

    /// Seeds a temp vault with known salt/head (so `cmd_anchor` reuses the
    /// commitment) and spins a mock JSON-RPC endpoint. When `bound`, the
    /// receipt is addressed to the registry with a matching publication
    /// log; otherwise it is a successful but unrelated receipt.
    async fn setup(bound: bool) -> Fixture {
        let dir = std::env::temp_dir().join(format!(
            "cv_anchor_bind_{}_{}",
            std::process::id(),
            if bound { "bound" } else { "unbound" }
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db_path = dir.join("vault.db");
        let store = LocalVaultStore::open(&db_path).unwrap();
        let seed = CheckpointEvidence::new(SALT, HEAD, 42161, REGISTRY, [0u8; 32], 0, 0);
        store.save_checkpoint_evidence(&seed).unwrap();
        crate::util::set_active_vault_path(Some(db_path));

        let commitment = CheckpointEvidence::compute_commitment(&SALT, &HEAD);
        let commitment_topic = format!("0x{}", hex::encode(commitment));
        let registry_hex = format!("0x{}", hex::encode(REGISTRY));
        let topic0_hex = format!("0x{}", hex::encode(COMMITMENT_PUBLISHED_TOPIC));

        let rpc_app = Router::new().route(
            "/",
            post(move |Json(payload): Json<Value>| {
                let registry_hex = registry_hex.clone();
                let topic0_hex = topic0_hex.clone();
                let commitment_topic = commitment_topic.clone();
                async move {
                    let method = payload["method"].as_str().unwrap_or("");
                    let id = payload["id"].clone();
                    match method {
                        "eth_getTransactionReceipt" => {
                            let mut result = json!({
                                "transactionHash": TX_HASH_HEX,
                                "blockNumber": "0x12345",
                                "status": "0x1",
                            });
                            if bound {
                                let to = registry_hex.clone();
                                result["to"] = json!(to.clone());
                                result["logs"] = json!([{
                                    "address": to,
                                    "topics": [
                                        topic0_hex,
                                        commitment_topic,
                                        "0x000000000000000000000000aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                                    ]
                                }]);
                            }
                            Json(json!({"jsonrpc": "2.0", "result": result, "id": id}))
                        }
                        "eth_call" => Json(json!({
                            "jsonrpc": "2.0",
                            "result": "0x0000000000000000000000000000000000000000000000000000000000012345",
                            "id": id
                        })),
                        "eth_blockNumber" => Json(json!({
                            "jsonrpc": "2.0",
                            "result": "0x12350",
                            "id": id
                        })),
                        _ => Json(json!({
                            "jsonrpc": "2.0",
                            "error": { "code": -32601, "message": "Method not found" },
                            "id": id
                        })),
                    }
                }
            }),
        );

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, rpc_app).await.unwrap();
        });

        Fixture {
            dir,
            rpc_url: format!("http://{}", addr),
        }
    }

    async fn invoke(fixture: &Fixture) -> Result<()> {
        cmd_anchor(
            Some(hex::encode(HEAD)),
            Some(fixture.rpc_url.clone()),
            Some(hex::encode(REGISTRY)),
            Some(42161),
            Some(TX_HASH_HEX.to_string()),
            None,
            false,
            None,
        )
        .await
    }

    #[tokio::test]
    async fn test_anchor_tx_hash_records_bound_receipt() {
        let _guard = VAULT_PATH_LOCK.lock().await;
        let fixture = setup(true).await;
        invoke(&fixture).await.unwrap();
        let store = LocalVaultStore::open(fixture.dir.join("vault.db")).unwrap();
        let saved = store.get_checkpoint_evidence(&HEAD).unwrap().unwrap();
        assert_eq!(
            saved.tx_hash,
            hex::decode(TX_HASH_HEX.trim_start_matches("0x")).unwrap()
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }

    #[tokio::test]
    async fn test_anchor_tx_hash_rejects_unbound_receipt() {
        let _guard = VAULT_PATH_LOCK.lock().await;
        let fixture = setup(false).await;
        let err = invoke(&fixture).await.unwrap_err();
        assert!(
            err.to_string().contains("did not publish"),
            "unexpected error: {err}"
        );
        let _ = std::fs::remove_dir_all(&fixture.dir);
    }
}

pub(crate) async fn cmd_verify_anchor(
    head_hex_opt: Option<String>,
    rpc_opt: Option<String>,
) -> Result<()> {
    let store = get_vault_store()?;
    let head_cid = match head_hex_opt {
        Some(h) => {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))?;
            if bytes.len() != 32 {
                bail!("Head CID must be 32 bytes hex string");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to verify")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    let evidence = store
        .get_checkpoint_evidence(&head_cid)?
        .context("No on-chain checkpoint evidence recorded for this snapshot head")?;

    let rpc_url = rpc_opt
        .or_else(|| std::env::var("ARBITRUM_RPC_URL").ok())
        .unwrap_or_else(|| "https://arb1.arbitrum.io/rpc".to_string());
    let mut contract_arr = [0u8; 20];
    if evidence.contract_address.len() == 20 {
        contract_arr.copy_from_slice(&evidence.contract_address);
    }
    let client =
        ciphervault_storage::ArbitrumAnchorClient::new(rpc_url, evidence.chain_id, contract_arr);

    println!("{}", "Verifying Checkpoint Evidence...".bold());
    let report = client.verify_evidence(&evidence).await?;

    println!("  Commitment:        {}", report.commitment_hex.yellow());
    println!(
        "  Salt Preimage:     {}",
        if report.preimage_valid {
            "Valid (Matches SHA-256('CIPHERVAULT-ANCHOR-V1' || salt || head_cid))".green()
        } else {
            "TAMPERED / INVALID".red()
        }
    );
    println!(
        "  Contract Registry: 0x{}",
        report.contract_address_hex.cyan()
    );
    println!("  Chain ID:          {}", report.chain_id);
    println!("  Recorded Block:    {}", report.recorded_block_number);
    println!("  Current Chain Blk: {}", report.current_chain_block);
    if report.tx_hash_hex != "0000000000000000000000000000000000000000000000000000000000000000" {
        println!("  Tx Hash:           0x{}", report.tx_hash_hex.dimmed());
    } else {
        println!("  Tx Hash:           None (Pre-submission proof)");
    }
    println!(
        "  On-Chain Status:   {}",
        if report.on_chain_confirmed {
            "Confirmed on Arbitrum Contract / Receipt".green().bold()
        } else {
            "Unsubmitted / Pending On-Chain".yellow()
        }
    );
    println!(
        "  Receipt Verified:  {}",
        if report.receipt_verified {
            "Yes (independent RPC receipt)".green()
        } else {
            "No (receipt unavailable or inconsistent)".yellow()
        }
    );

    let stage_str = match report.finality_stage {
        ciphervault_storage::AnchorFinalityStage::Pending => "Pending".yellow(),
        ciphervault_storage::AnchorFinalityStage::SequencerConfirmed { block_number } => {
            format!("Sequencer Confirmed (L2 block {})", block_number).green()
        }
        ciphervault_storage::AnchorFinalityStage::L2Confirmed { block_number } => format!(
            "L2 Confirmed (L2 block {} — L1 settlement not verified)",
            block_number
        )
        .green()
        .bold(),
        ciphervault_storage::AnchorFinalityStage::DeeplyConfirmed { block_number } => format!(
            "Deeply Confirmed on L2 (L2 block {} — L1 settlement not verified)",
            block_number
        )
        .green()
        .bold(),
    };
    println!("  Finality Stage:    {}", stage_str);

    Ok(())
}
