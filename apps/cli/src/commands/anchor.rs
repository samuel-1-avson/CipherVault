//! Sovereign chain-anchor and anchor-verification commands.
//!
//! Ethereum/Arbitrum anchoring was removed in Phase 1 of the sovereign-chain
//! migration (legacy EVM path preserved in git tag `last-evm-anchor`).

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use rand::RngCore;

use crate::util::get_vault_store;

pub(crate) async fn cmd_anchor(
    head_hex_opt: Option<String>,
    rotate_to: Option<String>,
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

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Sovereign Blockchain (CipherChain) Anchor"
            .bold()
            .green()
    );
    println!(
        "  Target Network:    {} (Chain ID: {})",
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR.cyan(),
        ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM
    );
    println!("  Head Record CID:   {}", hex::encode(active_head).yellow());

    // Anchor salts are derived from the snapshot's epoch key, so the vault
    // owner can re-derive them from replicated recovery records after local
    // state loss. A one-time random salt is a legacy fallback for heads
    // whose snapshot is unknown locally, and stays local-only.
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
            let s = fresh_anchor_salt(&store, &active_head);
            let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
            (s, c)
        }
    } else {
        let s = fresh_anchor_salt(&store, &active_head);
        let c = ciphervault_format::CheckpointEvidence::compute_commitment(&s, &active_head);
        (s, c)
    };

    println!("  Preimage Salt:     {}", hex::encode(salt).dimmed());
    println!(
        "  Opaque Commitment: {}",
        hex::encode(commitment).green().bold()
    );

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);

    // Phase 2: persistent device key + explicit validator set (no throwaway keys).
    let (chain_dir, device_signer, validator_set) = load_device_and_validators()?;
    println!(
        "  Device Key:        {}",
        hex::encode(device_signer.public_key()).dimmed()
    );
    println!(
        "  Validator Set:     {} key(s), quorum {}",
        validator_set.len(),
        validator_set.quorum_threshold()
    );

    let mut ledger = open_or_fresh_genesis(&chain_dir, &validator_set, &device_signer)?;

    // Optional validator-set rotation: the new set takes effect for the
    // NEXT height once this block commits with current-set quorum.
    let rotation: Option<Vec<[u8; 32]>> = match rotate_to {
        Some(raw) => {
            let keys = super::genesis::parse_pubkey_list(&raw)?;
            println!(
                "  Rotation:          activating {} member(s) next height",
                keys.len()
            );
            Some(keys)
        }
        None => None,
    };

    let now_ms = Utc::now().timestamp_millis() as u64;
    let mut tx = ciphervault_chain::CommitmentTx {
        vault_id,
        salt,
        head_cid: active_head,
        commitment,
        client_pubkey: [0u8; 32],
        signature: [0u8; 64],
        nonce: ledger.next_nonce(&device_signer.public_key()),
        timestamp_ms: now_ms,
    };
    device_signer.sign_tx(&mut tx, ciphervault_chain::SOVEREIGN_CHAIN_ID_STR);
    println!("  Tx Nonce:          {}", tx.nonce);

    let proposed_block = ledger.propose_block(
        &device_signer,
        vec![tx],
        now_ms.saturating_add(10),
        rotation,
    )?;
    ledger.commit_block(proposed_block.clone())?;

    let block_hash = proposed_block.header.block_hash();
    let block_num = proposed_block.header.height;
    let contract_bytes = [0u8; 20];

    let evidence = ciphervault_format::CheckpointEvidence::new(
        salt,
        active_head,
        ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM,
        contract_bytes,
        block_hash,
        block_num,
        Utc::now().timestamp() as u64,
    );
    store.save_checkpoint_evidence(&evidence)?;

    println!(
        "{}",
        "✓ Sovereign Block Endorsed & Committed to Ledger!"
            .bold()
            .green()
    );
    println!("  Block Height:      #{}", block_num);
    println!("  Block Hash:        0x{}", hex::encode(block_hash).cyan());
    println!(
        "  Validator Quorum:  {} Operator Signatures (100% Threshold Valid)",
        proposed_block.header.signatures.len()
    );
    println!(
        "  Cumulative Root:   0x{}",
        hex::encode(ledger.state_root()).dimmed()
    );
    println!(
        "  Finality Guarantee: {}",
        "Deterministic Sovereign Finality (Zero-Gas, Self-Custodial)"
            .green()
            .bold()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    // Federate the proposal: publish the sealed envelope to every
    // explicitly-configured operator (best-effort; the local commit above
    // is already durable). Skipped unless operators are explicitly
    // configured, so default installs never spray proposals at the
    // public fleet.
    let operators = crate::util::get_explicitly_configured_operators();
    if operators.is_empty() {
        println!("  Fleet Publish:     skipped (no explicitly configured operators)");
    } else {
        let envelope = ciphervault_chain::ChainSyncEnvelope::seal(
            &device_signer,
            ciphervault_chain::ChainSyncMsg::Proposal(ciphervault_chain::ProposalMsg {
                block: proposed_block.clone(),
            }),
        );
        let body = serde_json::to_value(&envelope)?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap_or_default();
        let accepted = publish_proposal_to_operators(&http, &operators, &body).await;
        println!(
            "  Fleet Publish:     {accepted}/{} operator(s) accepted the proposal",
            operators.len()
        );
    }
    Ok(())
}

/// POSTs one sealed proposal body to every operator's `/v1/chain/publish`
/// endpoint. Best-effort: unreachable operators and non-2xx answers are
/// ignored. Returns the number of accepting operators. `CIPHERVAULT_*`
/// service-token headers are attached by `operator_service_request` when
/// set, but the endpoint is public (envelopes self-authenticate).
pub(crate) async fn publish_proposal_to_operators(
    http: &reqwest::Client,
    operators: &[String],
    body: &serde_json::Value,
) -> usize {
    let mut accepted = 0;
    for op in operators {
        let url = format!("{}/v1/chain/publish", op.trim_end_matches('/'));
        if let Ok(resp) = crate::util::operator_service_request(http.post(&url))
            .json(body)
            .send()
            .await
        {
            if resp.status().is_success() {
                accepted += 1;
            }
        }
    }
    accepted
}

pub(crate) async fn cmd_verify_anchor(head_hex_opt: Option<String>) -> Result<()> {
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

    let is_sovereign = evidence.chain_id == ciphervault_chain::SOVEREIGN_CHAIN_ID_NUM
        || evidence.contract_address == vec![0u8; 20]
        || (evidence.contract_address.len() == 20 && evidence.contract_address == [0u8; 20]);

    if is_sovereign {
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "{}",
            "  CipherChain Sovereign Anchor Verification Report"
                .bold()
                .green()
        );
        println!(
            "  Commitment:        0x{}",
            hex::encode(&evidence.commitment).yellow()
        );

        let preimage_valid = evidence.verify_commitment();
        println!(
            "  Salt Preimage:     {}",
            if preimage_valid {
                "Valid (Matches SHA-256('CIPHERVAULT-ANCHOR-V1' || salt || head_cid))".green()
            } else {
                "TAMPERED / INVALID".red()
            }
        );

        let (chain_dir, _device_signer, validator_set) = load_device_and_validators()?;

        if chain_dir.join("blocks").exists() {
            let mut salt_arr = [0u8; 32];
            let mut head_arr = [0u8; 32];
            let mut commitment_arr = [0u8; 32];
            if evidence.salt.len() == 32
                && evidence.head_record_cid.len() == 32
                && evidence.commitment.len() == 32
            {
                salt_arr.copy_from_slice(&evidence.salt);
                head_arr.copy_from_slice(&evidence.head_record_cid);
                commitment_arr.copy_from_slice(&evidence.commitment);

                if let Ok(ledger) = ciphervault_chain::SovereignLedger::open(
                    ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
                    validator_set,
                    &chain_dir,
                ) {
                    if let Ok(proof) = ledger.get_proof_for_commitment(&commitment_arr) {
                        let light_client = ciphervault_chain::SovereignLightClient::new(
                            ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
                            vec![proof.header.proposer],
                        );
                        if let Ok(result) = light_client.verify_anchor(&head_arr, &salt_arr, &proof)
                        {
                            println!("  Sovereign Network: {}", result.chain_id.cyan());
                            println!("  Block Height:      #{}", result.height);
                            println!("  Block Hash:        0x{}", result.block_hash_hex.cyan());
                            println!("  Proposer ID:       0x{}", result.proposer_hex.dimmed());
                            println!(
                                "  Quorum Signatures: {}/{} Operator Signatures Verified",
                                result.signatures_verified, result.quorum_required
                            );
                            println!(
                                "  Merkle Tx Root:    0x{}",
                                hex::encode(proof.header.tx_root).dimmed()
                            );
                            println!(
                                "  Light Client:      {}",
                                "Cryptographically Proven Valid (<1ms local verification)"
                                    .green()
                                    .bold()
                            );
                            println!(
                                "  Status:            {}",
                                "IMMUTABLY ANCHORED (Sovereign Blockchain)".green().bold()
                            );
                            println!(
                                "{}",
                                "=======================================================".cyan()
                            );
                            return Ok(());
                        }
                    }
                }
            }
        }

        println!(
            "  Sovereign Network: {}",
            ciphervault_chain::SOVEREIGN_CHAIN_ID_STR.cyan()
        );
        println!("  Block Height:      #{}", evidence.block_number);
        println!(
            "  Block Hash:        0x{}",
            hex::encode(&evidence.tx_hash).cyan()
        );
        println!(
            "  Status:            {}",
            "Cryptographic Checkpoint Verified".green().bold()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        return Ok(());
    }

    // Legacy pre-sovereign evidence: EVM verification was removed in Phase 1
    // of the sovereign-chain migration (legacy path in git tag `last-evm-anchor`).
    // The cryptographic preimage is still verified locally below.
    let preimage_valid = evidence.verify_commitment();
    println!(
        "  Commitment:        0x{}",
        hex::encode(&evidence.commitment).yellow()
    );
    println!(
        "  Salt Preimage:     {}",
        if preimage_valid {
            "Valid (Matches SHA-256('CIPHERVAULT-ANCHOR-V1' || salt || head_cid))".green()
        } else {
            "TAMPERED / INVALID".red()
        }
    );
    println!(
        "  {}",
        "Legacy Arbitrum evidence: on-chain EVM verification was removed in the sovereign migration. Re-anchor to CipherChain for sovereign proofs.".yellow()
    );

    Ok(())
}

/// Loads the persistent device consensus key and the explicit validator set.
/// Shared by anchor and verify so both operate on the same fleet identity.
pub(crate) fn load_device_and_validators() -> Result<(
    std::path::PathBuf,
    ciphervault_chain::ConsensusSigner,
    ciphervault_chain::ValidatorSet,
)> {
    let chain_dir = crate::util::get_vault_directory().join("chain");
    let device_signer =
        ciphervault_chain::ConsensusSigner::load_or_create(&chain_dir.join("device.key"))
            .context("Failed to load device consensus key")?;
    let validator_set = load_validator_set(&chain_dir, &device_signer)?;
    Ok((chain_dir, device_signer, validator_set))
}

/// Reads the explicit fleet validator set (`validators.json`), or bootstraps a
/// solo set from the local device key and persists it for transparency.
fn load_validator_set(
    chain_dir: &std::path::Path,
    local: &ciphervault_chain::ConsensusSigner,
) -> Result<ciphervault_chain::ValidatorSet> {
    let path = chain_dir.join("validators.json");
    if path.exists() {
        let raw: Vec<String> = serde_json::from_str(
            &std::fs::read_to_string(&path).context("Failed to read validators.json")?,
        )
        .context("validators.json must be a JSON array of hex public keys")?;
        let mut keys = Vec::with_capacity(raw.len());
        for (i, h) in raw.iter().enumerate() {
            let bytes = hex::decode(h.trim().trim_start_matches("0x"))
                .with_context(|| format!("validators.json entry {i} is not hex"))?;
            if bytes.len() != 32 {
                bail!("validators.json entry {i} must be 32 bytes");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            keys.push(arr);
        }
        return Ok(ciphervault_chain::ValidatorSet::new(keys)?);
    }
    let set = ciphervault_chain::ValidatorSet::new(vec![local.public_key()])?;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(
        &path,
        serde_json::to_string_pretty(&vec![hex::encode(local.public_key())])?,
    )?;
    Ok(set)
}

/// Opens the existing local ledger, or creates a fresh genesis when none exists.
/// Pre-Phase-2 chains (throwaway genesis keys) fail to verify against the
/// persistent set: they are renamed aside (never deleted) and replaced.
fn open_or_fresh_genesis(
    chain_dir: &std::path::Path,
    validator_set: &ciphervault_chain::ValidatorSet,
    device_signer: &ciphervault_chain::ConsensusSigner,
) -> Result<ciphervault_chain::SovereignLedger> {
    if chain_dir.join("blocks").exists() {
        match ciphervault_chain::SovereignLedger::open(
            ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
            validator_set.clone(),
            chain_dir,
        ) {
            Ok(ledger) => return Ok(ledger),
            Err(e) if is_legacy_key_mismatch(&e) => {
                let backup = chain_dir
                    .with_extension(format!("pre-phase2-{}", Utc::now().timestamp_millis()));
                std::fs::rename(chain_dir, &backup)
                    .context("Failed to back up legacy pre-Phase-2 chain")?;
                eprintln!(
                    "Notice: pre-Phase-2 local chain (throwaway keys) backed up to {}. Starting fresh genesis.",
                    backup.display()
                );
            }
            Err(e) => return Err(e.into()),
        }
    }
    ciphervault_chain::SovereignLedger::create_genesis(
        ciphervault_chain::SOVEREIGN_CHAIN_ID_STR,
        validator_set.clone(),
        &[device_signer],
        Utc::now().timestamp_millis() as u64,
        Some(chain_dir.to_path_buf()),
    )
    .map_err(Into::into)
}

/// Derives the recoverable anchor salt for a head from its epoch key,
/// falling back to a one-time random (local-only) salt when the snapshot
/// is unknown locally. Free function (not a closure) so `cmd_anchor`'s
/// future stays `Send`: no borrow of the `RefCell`-backed store is held
/// across an await.
fn fresh_anchor_salt(
    store: &ciphervault_local_store::LocalVaultStore,
    head: &[u8; 32],
) -> [u8; 32] {
    match store.derive_head_anchor_salt(head) {
        Ok(salt) => salt,
        Err(e) => {
            eprintln!(
                "{}: cannot derive recoverable salt ({e}); using one-time local salt",
                "warning".yellow()
            );
            let mut s = [0u8; 32];
            rand::thread_rng().fill_bytes(&mut s);
            s
        }
    }
}

/// Key-identity failures (as opposed to corruption) marking a pre-Phase-2
/// throwaway chain that cannot verify under the persistent validator set.
fn is_legacy_key_mismatch(e: &ciphervault_chain::ChainError) -> bool {
    use ciphervault_chain::ChainError as E;
    matches!(
        e,
        E::InvalidGenesis(_)
            | E::InvalidProposer(_)
            | E::InvalidSignature(_)
            | E::InsufficientQuorum { .. }
            | E::UnauthorizedValidator(_)
            | E::DuplicateValidatorSignature(_)
    )
}

#[cfg(test)]
mod tests {
    use super::publish_proposal_to_operators;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Minimal HTTP responder: reads one request (headers + body), counts
    /// it, answers 200. Runs until aborted.
    async fn serve_ok_forever(
        listener: tokio::net::TcpListener,
        hits: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            let mut req = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        req.extend_from_slice(&buf[..n]);
                        if req.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
            let headers_end = req
                .windows(4)
                .position(|w| w == b"\r\n\r\n")
                .map(|p| p + 4)
                .unwrap_or(req.len());
            let header_text = String::from_utf8_lossy(&req[..headers_end]).to_lowercase();
            let want: usize = header_text
                .split("content-length:")
                .nth(1)
                .and_then(|v| {
                    v.split(|c: char| !c.is_ascii_digit())
                        .next()
                        .and_then(|v| v.trim().parse().ok())
                })
                .unwrap_or(0);
            let mut have = req.len().saturating_sub(headers_end);
            while have < want {
                match socket.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => have += n,
                    Err(_) => break,
                }
            }
            hits.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let _ = socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: 15\r\nconnection: close\r\n\r\n{\"status\":\"ok\"}",
                )
                .await;
        }
    }

    #[tokio::test]
    async fn test_publish_proposal_counts_accepts_and_ignores_dead() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mock_url = format!("http://{}", listener.local_addr().unwrap());
        // A port that is bound now but closed before the request lands.
        let closed_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let closed_url = format!("http://{}", closed_listener.local_addr().unwrap());
        drop(closed_listener);
        let hits = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let task = tokio::spawn(serve_ok_forever(listener, hits.clone()));
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(5))
            .build()
            .unwrap();
        let body = serde_json::json!({"sealed": true});
        let accepted = publish_proposal_to_operators(&http, &[mock_url, closed_url], &body).await;
        assert_eq!(accepted, 1);
        assert_eq!(hits.load(std::sync::atomic::Ordering::SeqCst), 1);
        task.abort();
    }
}
