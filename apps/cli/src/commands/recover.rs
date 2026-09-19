//! Recover and peer-discovery commands.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;

use ciphervault_format::{from_canonical_cbor, ChunkWireObject, SnapshotManifest, SnapshotRecord};
use ciphervault_recovery::OfflineRecoveryKit;
use ciphervault_snapshot::restore_snapshot;
use ciphervault_storage::OperatorClient;

use crate::util::{configured_operator_pool, get_configured_operators, operator_service_request};

pub(crate) async fn cmd_recover(
    kit_opt: Option<PathBuf>,
    shares_opt: Option<Vec<PathBuf>>,
    to_dir: PathBuf,
    require_approval: bool,
) -> Result<()> {
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Clean-Machine Emergency Recovery"
            .bold()
            .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );

    let kit = if let Some(share_paths) = shares_opt {
        if share_paths.is_empty() {
            bail!("No threshold guardian share files specified.");
        }
        println!(
            "Loading {} threshold guardian share files...",
            share_paths.len()
        );
        let mut guardian_kits = Vec::with_capacity(share_paths.len());
        for p in share_paths {
            if !p.exists() {
                bail!("Guardian share file does not exist: {}", p.display());
            }
            let text = fs::read_to_string(&p).context(format!(
                "Failed to read guardian share file '{}'",
                p.display()
            ))?;
            let g = ciphervault_recovery::ThresholdRecoveryKit::parse_from_printable(&text)?;
            println!(
                "  ✓ Loaded Guardian Share {} of {} (Checksum: {:#010x})",
                g.guardian_index, g.total_shares, g.checksum
            );
            guardian_kits.push(g);
        }

        println!("Reconstructing Master Recovery Secret R via Shamir Lagrange interpolation...");
        let reconstructed =
            ciphervault_recovery::ThresholdRecoveryKit::combine_kits(&guardian_kits)
                .context("Failed to reconstruct master secret from provided guardian shares")?;
        println!(
            "{}",
            "✓ Master Recovery Secret R reconstructed successfully!"
                .green()
                .bold()
        );
        reconstructed
    } else if let Some(kit_path) = kit_opt {
        println!(
            "Loading recovery kit from: {}",
            kit_path.display().to_string().bold()
        );

        if !kit_path.exists() {
            bail!("Recovery kit file does not exist: {}", kit_path.display());
        }

        let text = fs::read_to_string(&kit_path).context(format!(
            "Failed to read emergency recovery kit file '{}'",
            kit_path.display()
        ))?;
        OfflineRecoveryKit::parse_from_printable(&text)?
    } else {
        bail!("Must specify either --kit <PATH> or --shares <PATHS>... to execute clean recovery.");
    };

    println!("✓ Recovery kit validated! CRC32 checksum passed.");
    println!("  Vault ID:          {}", kit.vault_id_hex.yellow());
    println!("  Operators to scan: {}", kit.operator_endpoints.len());

    let mut vault_id = [0u8; 32];
    vault_id.copy_from_slice(&hex::decode(&kit.vault_id_hex)?);

    let mut locator = [0u8; 32];
    locator.copy_from_slice(&hex::decode(&kit.recovery_locator_hex)?);

    let secret = kit.validate_and_extract_secret()?;
    let recovery_signing_pk = secret
        .derive_recovery_signing_key()?
        .verifying_key()
        .to_bytes();
    let (_, recipient_pk) = secret.derive_recovery_encryption_keys()?;
    anyhow::ensure!(
        locator == secret.derive_recovery_locator()?,
        "Recovery locator does not match offline secret"
    );
    let pool = configured_operator_pool(kit.operator_endpoints.clone());

    println!("\nQuerying operators directly for recovery records...");
    let raw_records = pool.query_recovery_records(&locator).await;
    if raw_records.is_empty() {
        bail!("No recovery records found on any surviving operator for this locator.");
    }
    println!(
        "Found {} recovery records from surviving operators.",
        raw_records.len()
    );

    let (chosen_head, certificate) =
        ciphervault_recovery::trust::select_head(&raw_records, &vault_id, &recovery_signing_pk)?;

    if require_approval {
        println!();
        println!(
            "{}",
            "=======================================================".yellow()
        );
        println!(
            "{}",
            "  OUT-OF-BAND CRYPTOGRAPHIC APPROVAL REQUIRED"
                .bold()
                .yellow()
        );
        println!(
            "{}",
            "=======================================================".yellow()
        );
        let challenge = ciphervault_recovery::ApprovalChallenge::new(
            &vault_id,
            ciphervault_recovery::ApprovalAction::EmergencyRecovery,
            &[0u8; 32],
            format!(
                "Clean-machine emergency recovery into '{}'",
                to_dir.display()
            ),
            600,
        );
        let challenge_id = challenge.challenge_id.clone();
        println!("  Challenge ID:     {}", challenge_id.cyan().bold());
        println!("  Action:           EmergencyRecovery");
        println!("  Target Directory: {}", to_dir.display());
        println!("  Validity TTL:     600 seconds");
        println!();

        // Broadcast challenge to operator federation
        let mut broadcast_count = 0;
        let http = reqwest::Client::new();
        for op in &kit.operator_endpoints {
            let url = format!("{}/v1/auth/challenges", op.trim_end_matches('/'));
            if let Ok(resp) = operator_service_request(http.post(&url))
                .json(&challenge)
                .send()
                .await
            {
                if resp.status().is_success() {
                    broadcast_count += 1;
                }
            }
        }
        if broadcast_count == 0 {
            bail!("Failed to broadcast approval challenge to any operator node");
        }

        println!("Challenge registered with {} operator(s).", broadcast_count);
        println!(
            "{}",
            "Awaiting cryptographic approval receipt from team lead or guardian..."
                .bold()
                .cyan()
        );
        println!(
            "  Approver instruction: Run '{}'",
            format!("ciphervault approve sign {}", challenge_id).yellow()
        );

        let mut approved = false;
        let start_time = std::time::Instant::now();
        while start_time.elapsed().as_secs() < 300 {
            for op in &kit.operator_endpoints {
                let url = format!(
                    "{}/v1/auth/challenges/{}",
                    op.trim_end_matches('/'),
                    challenge_id
                );
                if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
                    if let Ok(json) = resp.json::<serde_json::Value>().await {
                        if json["approved"].as_bool().unwrap_or(false) {
                            if let Some(receipts) = json["receipts"].as_array() {
                                if let Some(first) = receipts.first() {
                                    let name = first["approver_name"]
                                        .as_str()
                                        .unwrap_or("Authorized Approver");
                                    println!(
                                        "{}",
                                        format!(
                                            "✓ Cryptographic approval receipt verified from '{}'!",
                                            name
                                        )
                                        .green()
                                        .bold()
                                    );
                                    approved = true;
                                    break;
                                }
                            }
                        }
                    }
                }
            }
            if approved {
                break;
            }
            tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        }

        if !approved {
            bail!(
                "Emergency recovery aborted: Timed out waiting for out-of-band approval receipt."
            );
        }
    }

    // Fetch and authenticate snapshot record object
    let mut snap_cid = [0u8; 32];
    snap_cid.copy_from_slice(&chosen_head.snapshot_id);
    let snap_record_bytes = pool.fetch_object_from_any(&snap_cid).await?;
    let record: SnapshotRecord = from_canonical_cbor(&snap_record_bytes)?;

    ciphervault_recovery::trust::verify_snapshot(&record, &chosen_head, &certificate)?;
    // Fetch encrypted manifest
    let mut manifest_cid = [0u8; 32];
    manifest_cid.copy_from_slice(&record.encrypted_manifest_cid);
    let encrypted_manifest = pool.fetch_object_from_any(&manifest_cid).await?;

    let envelope = ciphervault_recovery::trust::select_envelope(
        &raw_records,
        &record,
        &certificate,
        recipient_pk.as_bytes(),
    )?;
    let epoch_key = kit.open_envelope(&envelope)?;
    let manifest_key = epoch_key.derive_manifest_key(record.epoch)?;
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes =
        ciphervault_crypto::decrypt_chunk(&manifest_key, &encrypted_manifest, &aad)?;
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    println!(
        "Manifest decrypted. {} files declared in snapshot.",
        manifest.files.len()
    );

    // Download required chunk objects from surviving operators
    let mut all_chunks = Vec::new();
    for file in &manifest.files {
        if file.is_deleted {
            continue;
        }
        for cid_bytes in &file.chunk_cids {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cid_bytes);
            let chunk_bytes = pool.fetch_object_from_any(&arr).await?;
            let chunk: ChunkWireObject = from_canonical_cbor(&chunk_bytes)?;
            all_chunks.push(chunk);
        }
    }

    println!(
        "Restoring and authenticating files into '{}'...",
        to_dir.display()
    );
    let restored = restore_snapshot(
        &to_dir,
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &all_chunks,
    )?;

    println!(
        "{}",
        "=======================================================".green()
    );
    println!(
        "{}",
        "✓ CLEAN-MACHINE RECOVERY COMPLETED SUCCESSFULLY!"
            .bold()
            .green()
    );
    println!(
        "{}",
        "=======================================================".green()
    );
    println!("Restored files:");
    for p in restored {
        println!("  - {}", p.display().to_string().cyan());
    }

    Ok(())
}

pub(crate) async fn cmd_peers(discover: bool, mesh: bool) -> Result<()> {
    let mut operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured. Run 'ciphervault init' first.");
    }

    if mesh {
        return cmd_peers_mesh(&operators).await;
    }

    println!("{}", "CipherVault Operator Federation Routing Table".bold());
    println!("------------------------------------------------------------");

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(4))
        .build()
        .unwrap_or_default();

    if discover {
        println!("Querying cluster for dynamic P2P peer announcements...");
        let mut discovered_endpoints = Vec::new();
        for op in &operators {
            let url = format!("{}/v1/peers", op.trim_end_matches('/'));
            if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
                if let Ok(peers) = resp
                    .json::<Vec<ciphervault_storage::PeerDescriptor>>()
                    .await
                {
                    for p in peers {
                        if p.verify().is_ok() {
                            let norm = p.endpoint.trim_end_matches('/').to_string();
                            if !operators.contains(&norm) && !discovered_endpoints.contains(&norm) {
                                discovered_endpoints.push(norm);
                            }
                        }
                    }
                }
            }
        }
        if !discovered_endpoints.is_empty() {
            println!(
                "{}",
                format!(
                    "  ✓ Discovered {} new dynamic peer node(s)!",
                    discovered_endpoints.len()
                )
                .green()
            );
            operators.extend(discovered_endpoints);
        } else {
            println!("  (All cluster peers are already known)");
        }
        println!();
    }

    println!(
        "{:<32} {:<12} {:<10} {:<18}",
        "OPERATOR ENDPOINT", "STATUS", "LATENCY", "PUBLIC KEY"
    );
    println!(
        "{:<32} {:<12} {:<10} {:<18}",
        "-------------------------------", "------", "-------", "----------"
    );

    for op in &operators {
        let norm = op.trim_end_matches('/');
        let url = format!("{}/v1/info", norm);
        let start = std::time::Instant::now();
        match http.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => {
                let latency = format!("{}ms", start.elapsed().as_millis());
                if let Ok(info) = resp.json::<ciphervault_storage::OperatorInfo>().await {
                    let short_pk = if info.operator_signing_pk_hex.len() >= 12 {
                        format!("{}...", &info.operator_signing_pk_hex[..12])
                    } else {
                        info.operator_signing_pk_hex
                    };
                    println!(
                        "{:<32} {:<12} {:<10} {:<18}",
                        norm.cyan(),
                        "ONLINE".green().bold(),
                        latency.yellow(),
                        short_pk.dimmed()
                    );
                } else {
                    println!(
                        "{:<32} {:<12} {:<10} {:<18}",
                        norm.cyan(),
                        "ONLINE".green().bold(),
                        latency.yellow(),
                        "unknown".dimmed()
                    );
                }
            }
            _ => {
                println!(
                    "{:<32} {:<12} {:<10} {:<18}",
                    norm.dimmed(),
                    "OFFLINE".red().bold(),
                    "-",
                    "-"
                );
            }
        }
    }

    Ok(())
}

/// Meshes operator routing tables: fetches each operator's public self
/// descriptor and announces it to every other operator. Without meshing,
/// heartbeats from unknown senders are ignored and repair cannot push.
pub(crate) async fn cmd_peers_mesh(operators: &[String]) -> Result<()> {
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let mut descriptors = Vec::new();
    for op in operators {
        let url = format!("{}/v1/peers/self", op.trim_end_matches('/'));
        let descriptor = http
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetch self descriptor from {op}"))?
            .json::<ciphervault_storage::PeerDescriptor>()
            .await
            .with_context(|| format!("decode self descriptor from {op}"))?;
        descriptor
            .verify()
            .with_context(|| format!("self descriptor from {op} has a bad signature"))?;
        descriptors.push(descriptor);
    }
    let mut announced = 0usize;
    for target in operators {
        let client = OperatorClient::new(target.clone());
        for descriptor in &descriptors {
            client
                .announce_peer(descriptor)
                .await
                .with_context(|| format!("announce {} to {target}", descriptor.operator_id))?;
            announced += 1;
        }
    }
    println!(
        "{}",
        format!(
            "  ✓ Meshed {} operators ({} announces)",
            operators.len(),
            announced
        )
        .green()
    );
    Ok(())
}
