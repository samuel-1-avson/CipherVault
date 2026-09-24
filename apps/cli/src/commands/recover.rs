//! Recover and peer-discovery commands.

use anyhow::{bail, Context, Result};
use chrono::Utc;
use colored::Colorize;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use std::fs;
use std::path::PathBuf;

use ciphervault_crypto::generate_signing_key;
use ciphervault_format::{
    from_canonical_cbor, ChunkWireObject, DeviceCertificate, GenesisRecord, SnapshotManifest,
    SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_recovery::OfflineRecoveryKit;
use ciphervault_snapshot::restore_snapshot;
use ciphervault_storage::invites::JoinInvite;
use ciphervault_storage::{OperatorClient, StorageError};

use crate::util::{
    configured_operator_pool, get_configured_operators, operator_service_request, DB_FILE,
    OPERATORS_FILE, VAULT_DIR,
};

pub(crate) async fn cmd_recover(
    kit_opt: Option<PathBuf>,
    shares_opt: Option<Vec<PathBuf>>,
    to_dir: PathBuf,
    require_approval: bool,
    force: bool,
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

    rebuild_store_after_recovery(
        &kit,
        &secret,
        &raw_records,
        &vault_id,
        &locator,
        &record,
        &chosen_head,
        &epoch_key,
        &to_dir,
        force,
    )?;

    Ok(())
}

/// Finds the vault's genesis record among the locator's recovery records.
/// Every push uploads the genesis CBOR as a content-addressed object and
/// appends it under the locator, so a wiped device can re-anchor trust:
/// the candidate must carry this vault's ID, pin the kit-derived recovery
/// key, and verify — a foreign or forged genesis never matches all three.
fn find_genesis_record(
    records: &[Vec<u8>],
    vault_id: &[u8; 32],
    recovery_pk: &[u8; 32],
) -> Option<GenesisRecord> {
    records
        .iter()
        .filter_map(|bytes| from_canonical_cbor::<GenesisRecord>(bytes).ok())
        .find(|genesis| {
            genesis.version == PROTOCOL_VERSION
                && genesis.vault_id.as_slice() == vault_id
                && genesis.recovery_signing_pk.as_slice() == recovery_pk
                && genesis.verify().is_ok()
        })
}

/// Rebuilds a working local store inside the restored directory so the
/// wiped device can `pull`, `push`, and see an overview immediately —
/// without it `recover` leaves files that no command can operate on.
/// Trust roots entirely in the offline kit: the original genesis is
/// re-fetched (never re-minted), the epoch key is the recovered one, and
/// the fresh device certificate is signed by the kit's recovery key at
/// the recovered authority generation so the next push authorizes.
#[allow(clippy::too_many_arguments)]
fn rebuild_store_after_recovery(
    kit: &OfflineRecoveryKit,
    secret: &ciphervault_crypto::RecoverySecret,
    raw_records: &[Vec<u8>],
    vault_id: &[u8; 32],
    locator: &[u8; 32],
    record: &SnapshotRecord,
    chosen_head: &ciphervault_format::HeadRecord,
    epoch_key: &ciphervault_crypto::VaultEpochKey,
    to_dir: &std::path::Path,
    force: bool,
) -> Result<()> {
    let recovery_sk = secret.derive_recovery_signing_key()?;
    let recovery_pk = recovery_sk.verifying_key().to_bytes();
    let Some(genesis) = find_genesis_record(raw_records, vault_id, &recovery_pk) else {
        bail!(
            "No genesis record found under this locator: the vault was never pushed with \
             recovery records, so no store can be rebuilt. Restore `.ciphervault` from a \
             surviving device backup and `pull` instead (copy+pull)."
        );
    };

    let store_dir = to_dir.join(VAULT_DIR);
    if store_dir.exists() && !force {
        bail!(
            "A store already exists at '{}'. Use '--force' to rebuild it from recovery.",
            store_dir.display()
        );
    }
    fs::create_dir_all(&store_dir)?;
    let db_path = store_dir.join(DB_FILE);
    if db_path.exists() {
        fs::remove_file(&db_path)?;
    }

    let mut device_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut device_id);
    let mut certificate_id = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut certificate_id);
    let device_sk = generate_signing_key();
    let store = LocalVaultStore::open(&db_path)?;
    store.init_vault_at_epoch(
        vault_id,
        &genesis,
        &device_sk,
        &device_id,
        epoch_key,
        locator,
        record.epoch,
    )?;

    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        certificate_id,
        device_signing_pk: device_sk.verifying_key().as_bytes().to_vec(),
        permissions: 0xFFFFFFFF,
        authority_generation: record.authority_generation,
        issued_at_utc: Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    cert.sign(&recovery_sk)?;
    store.save_device_certificate(&cert)?;
    store.set_head(chosen_head)?;

    let ops_json = serde_json::to_string_pretty(&kit.operator_endpoints)?;
    fs::write(store_dir.join(OPERATORS_FILE), ops_json)?;

    println!();
    println!(
        "{}",
        "✓ Local store rebuilt — this directory is a working vault again."
            .bold()
            .green()
    );
    println!(
        "  Vault:   {} (epoch {})",
        hex::encode(vault_id).yellow(),
        record.epoch
    );
    println!(
        "  Next:    cd {} && ciphervault pull",
        to_dir.display().to_string().cyan()
    );
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

/// Reads a 32-byte seed file into a signing key (fleet offline ops).
fn read_seed_file(path: &PathBuf) -> Result<SigningKey> {
    let bytes = fs::read(path).with_context(|| format!("read key file {}", path.display()))?;
    if bytes.len() != 32 {
        bail!("key file must contain exactly 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&seed))
}

/// Prints the fleet public key for a seed file: the value fleet nodes
/// pin as `CIPHERVAULT_FLEET_KEY`.
pub(crate) fn cmd_invite_pubkey(fleet_key_file: PathBuf) -> Result<()> {
    let fleet_key = read_seed_file(&fleet_key_file)?;
    println!("{}", hex::encode(fleet_key.verifying_key().to_bytes()));
    Ok(())
}

/// Decodes text bytes as UTF-8, or as UTF-16 when a BOM says so.
/// PowerShell `>` redirection writes UTF-16LE, which `read_to_string`
/// rejects outright — and tickets/keys files are exactly what admins
/// redirect. BOM-less input must be valid UTF-8.
fn decode_text_bytes(bytes: &[u8]) -> Result<String> {
    let endian: Option<bool> = match bytes {
        [0xFF, 0xFE, ..] => Some(false),
        [0xFE, 0xFF, ..] => Some(true),
        _ => None,
    };
    match endian {
        None => String::from_utf8(bytes.to_vec()).context("file is not valid UTF-8"),
        Some(big) => {
            let (pairs, trailing) = bytes[2..].as_chunks::<2>();
            if !trailing.is_empty() {
                bail!("UTF-16 file has an odd byte count");
            }
            let units: Vec<u16> = pairs
                .iter()
                .map(|pair| {
                    if big {
                        u16::from_be_bytes(*pair)
                    } else {
                        u16::from_le_bytes(*pair)
                    }
                })
                .collect();
            String::from_utf16(&units).context("file is not valid UTF-16")
        }
    }
}

/// Reads a small text file (ticket, keys list), tolerating UTF-16 and a
/// UTF-8 BOM: both are what Windows tooling actually produces.
fn read_text_file(path: &PathBuf, what: &str) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {what} file {}", path.display()))?;
    decode_text_bytes(&bytes).with_context(|| {
        format!(
            "decode {what} file {} (expected UTF-8 or UTF-16 text)",
            path.display()
        )
    })
}

/// Reads node public keys for batch issuance: one 64-hex key per line,
/// blank lines and `#` comments skipped. Errors name the bad line.
fn read_node_keys_file(path: &PathBuf) -> Result<Vec<String>> {
    let raw = read_text_file(path, "keys")?;
    let mut keys = Vec::new();
    for (index, line) in raw.trim_start_matches('\u{FEFF}').lines().enumerate() {
        let key = line.trim();
        if key.is_empty() || key.starts_with('#') {
            continue;
        }
        let valid = key.len() == 64 && key.chars().all(|c| c.is_ascii_hexdigit());
        if !valid {
            bail!(
                "keys file {} line {}: expected 64-hex node public key",
                path.display(),
                index + 1
            );
        }
        keys.push(key.to_string());
    }
    if keys.is_empty() {
        bail!("keys file {} contains no node keys", path.display());
    }
    Ok(keys)
}

/// Issues one ticket per node key. Pure issuance loop behind both the
/// single and batch CLI shapes.
fn issue_tickets(fleet_key: &SigningKey, keys: &[String], ttl: u64) -> Result<Vec<JoinInvite>> {
    keys.iter()
        .map(|node_pk| {
            JoinInvite::issue(fleet_key, node_pk.clone(), ttl)
                .map_err(|error| anyhow::anyhow!(error.to_string()))
        })
        .collect()
}

/// Issues fleet-signed join invites for new operator node keys. Fully
/// offline: the fleet seed never leaves this machine, and the ticket
/// JSON is handed to joiners out of band. Single key emits one ticket
/// object; `--keys-file` emits an array of tickets in file order.
/// `--out` writes UTF-8 directly and is the blessed path on Windows,
/// where shell `>` redirection produces UTF-16.
pub(crate) fn cmd_invite_issue(
    node_pk: Option<String>,
    keys_file: Option<PathBuf>,
    ttl: u64,
    fleet_key_file: PathBuf,
    out: Option<PathBuf>,
) -> Result<()> {
    let keys = match (node_pk, keys_file) {
        (Some(pk), None) => vec![pk],
        (None, Some(path)) => read_node_keys_file(&path)?,
        _ => bail!("pass exactly one of <node-pk> or --keys-file"),
    };
    let fleet_key = read_seed_file(&fleet_key_file)?;
    let batch = keys.len() > 1;
    let tickets = issue_tickets(&fleet_key, &keys, ttl)?;
    let rendered = if batch {
        serde_json::to_string_pretty(&tickets)?
    } else {
        serde_json::to_string_pretty(&tickets[0])?
    };
    if let Some(path) = &out {
        fs::write(path, format!("{rendered}\n"))
            .with_context(|| format!("write ticket file {}", path.display()))?;
        eprintln!(
            "{}",
            format!(
                "Wrote {} to {} (UTF-8).",
                if batch {
                    format!("{} tickets", tickets.len())
                } else {
                    "ticket".to_string()
                },
                path.display()
            )
            .green()
        );
    } else {
        println!("{rendered}");
        if batch {
            eprintln!(
                "Issued {} tickets (one per key, in file order).",
                tickets.len()
            );
        }
    }
    // Stderr only: stdout stays pure JSON for shell redirects.
    if ttl <= 86400 {
        eprintln!(
            "{}",
            "Tip: grace rejoin lasts as long as the ticket — issue at least 7 days (--ttl 604800) so a lapsed node can rejoin without a fresh ticket."
                .yellow()
        );
    }
    Ok(())
}

/// Actionable next step for a failed ticket join, by fleet status code.
/// Playbook §10 failure hints, printed where the joiner sees them.
fn join_failure_hint(status: u16) -> Option<&'static str> {
    match status {
        403 => Some(
            "ticket rejected (bad, expired, or for a different node key) — ask your fleet admin for a fresh ticket",
        ),
        409 => Some(
            "ticket already spent (each ticket admits once) — ask your fleet admin for a fresh ticket",
        ),
        _ => None,
    }
}

/// Actionable next step for a failed liveness refresh, by status code.
fn refresh_failure_hint(status: u16) -> Option<&'static str> {
    match status {
        404 => Some(
            "the fleet has no entry for this node (refresh lapsed over 24h) — rejoin with your ORIGINAL ticket while it is valid, then refresh regularly",
        ),
        _ => None,
    }
}

fn server_status(error: &StorageError) -> Option<u16> {
    match error {
        StorageError::ServerError { status, .. } => Some(*status),
        _ => None,
    }
}

fn print_hint(hint: Option<&'static str>) {
    if let Some(hint) = hint {
        eprintln!("{}", hint.yellow());
    }
}

/// Decodes a ticket file, tolerating a UTF-8 BOM: Windows editors (e.g.
/// Notepad) add one, and a ticket handed out of band often passes
/// through them.
fn decode_ticket(raw: &str) -> Result<JoinInvite> {
    serde_json::from_str(raw.trim_start_matches('\u{FEFF}'))
        .context("decode join invite ticket (expected JSON)")
}

/// Plain-language rendering of a fleet standing for beginners.
pub(crate) fn describe_standing(status: &str) -> String {
    match status {
        "probation" => "in probation (stores data; full trust after a day of uptime)".to_string(),
        "full" => "a full member".to_string(),
        "unknown" => "not in the fleet".to_string(),
        other => format!("in an unexpected state ({other:?})"),
    }
}

/// Fetches the joiner's own fresh self-signed descriptor from its node.
pub(crate) async fn fetch_self_descriptor(
    http: &reqwest::Client,
    node: &str,
) -> Result<ciphervault_storage::PeerDescriptor> {
    let url = format!("{}/v1/peers/self", node.trim_end_matches('/'));
    let descriptor = http
        .get(&url)
        .send()
        .await
        .with_context(|| format!("fetch self descriptor from {node}"))?
        .json::<ciphervault_storage::PeerDescriptor>()
        .await
        .with_context(|| format!("decode self descriptor from {node}"))?;
    descriptor
        .verify()
        .with_context(|| format!("self descriptor from {node} has a bad signature"))?;
    Ok(descriptor)
}

/// Presents a join ticket to fleet nodes: the joiner's fresh descriptor
/// plus the fleet-signed invite go to every `--via` endpoint (default:
/// configured operators). Each node verifies the ticket against its
/// pinned fleet key and admits the node into probation.
pub(crate) async fn cmd_invite_join(
    ticket: PathBuf,
    node: String,
    via: Option<Vec<String>>,
) -> Result<()> {
    let raw = read_text_file(&ticket, "ticket")?;
    let invite = decode_ticket(&raw)?;
    let targets = match via {
        Some(endpoints) if !endpoints.is_empty() => endpoints,
        _ => get_configured_operators(),
    };
    if targets.is_empty() {
        bail!("No fleet endpoints: pass --via or run 'ciphervault init' first.");
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let descriptor = fetch_self_descriptor(&http, &node).await?;
    if !descriptor
        .signing_pk_hex
        .eq_ignore_ascii_case(&invite.node_pk_hex)
    {
        bail!("Ticket is for a different node key than this node presents.");
    }
    for target in &targets {
        let client = OperatorClient::new(target.clone());
        let response = match client.join_with_invite(&descriptor, &invite).await {
            Ok(response) => response,
            Err(error) => {
                print_hint(server_status(&error).and_then(join_failure_hint));
                return Err(anyhow::anyhow!(error.to_string()))
                    .with_context(|| format!("join via {target}"));
            }
        };
        println!(
            "{}",
            format!(
                "  ✓ {} admitted by {} ({} of {} peers)",
                response.operator_id, target, response.status, response.peer_count,
            )
            .green()
        );
    }
    Ok(())
}

/// Refreshes liveness against every `target`, returning each endpoint's
/// reported standing (`"probation"`/`"full"`). Unknown joiners come back
/// as `"unknown"` instead of failing, so status-style callers can tell
/// a never-joined node from a failed refresh.
pub(crate) async fn refresh_standing(
    descriptor: &ciphervault_storage::PeerDescriptor,
    targets: &[String],
) -> Result<Vec<(String, String)>> {
    let mut standings = Vec::new();
    for target in targets {
        let client = OperatorClient::new(target.clone());
        match client.refresh_join(descriptor).await {
            Ok(response) => standings.push((target.clone(), response.status)),
            Err(StorageError::ServerError { status: 404, .. }) => {
                standings.push((target.clone(), "unknown".to_string()));
            }
            Err(error) => {
                return Err(anyhow::anyhow!(error.to_string()))
                    .with_context(|| format!("refresh via {target}"));
            }
        }
    }
    Ok(standings)
}

/// Re-presents the joiner's fresh descriptor to fleet nodes to prove
/// liveness (keeps the routing entry alive and advances graduation).
/// Same endpoint defaulting as join; no ticket needed.
pub(crate) async fn cmd_invite_refresh(node: String, via: Option<Vec<String>>) -> Result<()> {
    let targets = match via {
        Some(endpoints) if !endpoints.is_empty() => endpoints,
        _ => get_configured_operators(),
    };
    if targets.is_empty() {
        bail!("No fleet endpoints: pass --via or run 'ciphervault init' first.");
    }
    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
        .unwrap_or_default();
    let descriptor = fetch_self_descriptor(&http, &node).await?;
    for (target, status) in refresh_standing(&descriptor, &targets).await? {
        if status == "unknown" {
            print_hint(refresh_failure_hint(404));
            bail!("{target} has no entry for this node (rejoin with your original ticket).");
        }
        println!(
            "{}",
            format!(
                "  ✓ {} refreshed by {} ({})",
                descriptor.operator_id, target, status
            )
            .green()
        );
    }
    Ok(())
}

#[cfg(test)]
mod invite_hint_tests {
    use super::*;

    fn server_error(status: u16) -> StorageError {
        StorageError::ServerError {
            status,
            message: "fleet said no".to_string(),
        }
    }

    #[test]
    fn join_hints_cover_ticket_failures() {
        assert!(join_failure_hint(403).unwrap().contains("fresh ticket"));
        assert!(join_failure_hint(409).unwrap().contains("already spent"));
        assert_eq!(join_failure_hint(500), None);
        assert_eq!(server_status(&server_error(403)), Some(403));
        assert_eq!(server_status(&StorageError::InvalidReceiptSignature), None);
    }

    #[test]
    fn refresh_hint_covers_lapsed_entry() {
        assert!(refresh_failure_hint(404).unwrap().contains("rejoin"));
        assert_eq!(refresh_failure_hint(500), None);
    }

    #[test]
    fn ticket_decode_tolerates_utf8_bom() {
        let ticket = serde_json::json!({
            "version": 1u8,
            "issuer_pk_hex": "ab",
            "node_pk_hex": "cd",
            "expires_utc": 1u64,
            "nonce_hex": "ef",
            "signature_hex": "00",
        });
        let plain = serde_json::to_string(&ticket).unwrap();
        let bomed = format!("\u{FEFF}{plain}");
        // Signature is not verified at decode time (the fleet does that).
        assert_eq!(
            decode_ticket(&plain).unwrap().node_pk_hex,
            decode_ticket(&bomed).unwrap().node_pk_hex
        );
        assert!(decode_ticket("not json").is_err());
    }

    #[test]
    fn keys_file_skips_blanks_and_comments_and_names_bad_lines() {
        let path = std::env::temp_dir().join(format!("cv-keys-{}.txt", rand::random::<u32>()));
        let good = "ab".repeat(32);
        std::fs::write(&path, format!("# comment\n\n  {good}  \n{good}\n")).unwrap();
        let keys = read_node_keys_file(&path).unwrap();
        assert_eq!(keys, vec![good.clone(), good]);
        std::fs::write(&path, "not-hex\n").unwrap();
        let error = read_node_keys_file(&path).unwrap_err();
        assert!(
            format!("{error:#}").contains("line 1"),
            "unexpected: {error:#}"
        );
        std::fs::write(&path, "# only comments\n\n").unwrap();
        assert!(read_node_keys_file(&path).is_err());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn batch_issuance_shape_is_one_ticket_per_key_in_order() {
        let fleet = ciphervault_crypto::generate_signing_key();
        let fleet_hex = hex::encode(fleet.verifying_key().to_bytes());
        let key_a = hex::encode([1u8; 32]);
        let key_b = hex::encode([2u8; 32]);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let tickets = issue_tickets(&fleet, &[key_a.clone(), key_b.clone()], 604800).unwrap();
        assert_eq!(tickets.len(), 2);
        assert_eq!(tickets[0].node_pk_hex, key_a);
        assert_eq!(tickets[1].node_pk_hex, key_b);
        assert_ne!(tickets[0].nonce_hex, tickets[1].nonce_hex);
        for ticket in &tickets {
            ticket.verify(&fleet_hex, now).unwrap();
        }
        // Batch stdout shape: a JSON array in file order.
        let value: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&tickets).unwrap()).unwrap();
        assert!(value.is_array());
        assert_eq!(value.as_array().unwrap().len(), 2);
    }

    #[test]
    fn standing_descriptions_stay_plain() {
        assert!(describe_standing("probation").contains("probation"));
        assert!(describe_standing("full").contains("full member"));
        assert!(describe_standing("unknown").contains("not in the fleet"));
        assert!(describe_standing("weird").contains("unexpected"));
    }

    #[test]
    fn text_decode_accepts_utf8_and_bom_marked_utf16() {
        assert_eq!(decode_text_bytes(b"{\"a\":1}").unwrap(), "{\"a\":1}");
        // UTF-16LE with BOM, as PowerShell `>` redirection writes it.
        let le: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain("{\"a\":1}".encode_utf16().flat_map(|u| u.to_le_bytes()))
            .collect();
        assert_eq!(decode_text_bytes(&le).unwrap(), "{\"a\":1}");
        // UTF-16BE with BOM.
        let be: Vec<u8> = [0xFE, 0xFF]
            .into_iter()
            .chain("{\"a\":1}".encode_utf16().flat_map(|u| u.to_be_bytes()))
            .collect();
        assert_eq!(decode_text_bytes(&be).unwrap(), "{\"a\":1}");
        // Garbage stays an error: odd-length UTF-16 is rejected rather
        // than truncated, lone surrogates fail, and BOM-less input must
        // be valid UTF-8.
        assert!(decode_text_bytes(&[0xFF, 0xFE, 0x41]).is_err());
        assert!(decode_text_bytes(&[0xFF, 0xFE, 0x00, 0xD8]).is_err());
        assert!(decode_text_bytes(&[0xC3, 0x28]).is_err());
    }

    #[test]
    fn keys_file_accepts_utf16_and_utf8_bom() {
        let dir = std::env::temp_dir();
        let path = dir.join(format!("cv-keys-{}.txt", rand::random::<u32>()));
        let key = "ab".repeat(32);
        // UTF-16LE file as PowerShell redirection would leave it.
        let mut bytes = vec![0xFF, 0xFE];
        for unit in format!("{key}\n").encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        std::fs::write(&path, &bytes).unwrap();
        assert_eq!(read_node_keys_file(&path).unwrap(), vec![key.clone()]);
        // A UTF-8 BOM (Windows editors) must not poison line 1.
        std::fs::write(&path, format!("\u{FEFF}{key}\n")).unwrap();
        assert_eq!(read_node_keys_file(&path).unwrap(), vec![key]);
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn issue_out_writes_utf8_ticket_file() {
        let dir = std::env::temp_dir();
        let tag = rand::random::<u32>();
        let seed_path = dir.join(format!("cv-seed-{tag}.bin"));
        let seed = ciphervault_crypto::generate_signing_key();
        std::fs::write(&seed_path, seed.to_bytes()).unwrap();
        let out_path = dir.join(format!("cv-ticket-{tag}.json"));
        let node_pk = hex::encode([7u8; 32]);
        cmd_invite_issue(
            Some(node_pk.clone()),
            None,
            604800,
            seed_path.clone(),
            Some(out_path.clone()),
        )
        .unwrap();
        let bytes = std::fs::read(&out_path).unwrap();
        assert!(
            !bytes.starts_with(&[0xFF, 0xFE]),
            "ticket file must be UTF-8, not UTF-16"
        );
        let ticket = decode_ticket(&String::from_utf8(bytes).unwrap()).unwrap();
        assert_eq!(ticket.node_pk_hex, node_pk);
        std::fs::remove_file(&seed_path).unwrap();
        std::fs::remove_file(&out_path).unwrap();
    }
}

#[cfg(test)]
mod genesis_find_tests {
    use super::*;
    use ciphervault_crypto::RecoverySecret;
    use ciphervault_format::to_canonical_cbor;

    fn signed_genesis(vault_id: &[u8; 32], secret: &RecoverySecret) -> (GenesisRecord, [u8; 32]) {
        let r_sk = secret.derive_recovery_signing_key().unwrap();
        let (_, r_enc_pk) = secret.derive_recovery_encryption_keys().unwrap();
        let mut genesis = GenesisRecord {
            version: PROTOCOL_VERSION,
            vault_id: vault_id.to_vec(),
            recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
            recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
            policy_digest: vec![0u8; 32],
            created_at_utc: 1000,
            creation_nonce: vec![1u8; 32],
            signature: Vec::new(),
        };
        genesis.sign(&r_sk).unwrap();
        (genesis, r_sk.verifying_key().to_bytes())
    }

    #[test]
    fn finds_genesis_among_mixed_records() {
        let vault_id = [0xAAu8; 32];
        let secret = RecoverySecret::generate();
        let (genesis, recovery_pk) = signed_genesis(&vault_id, &secret);
        // Locator records mix generations and types: junk bytes, a foreign
        // vault's genesis, then ours.
        let other_secret = RecoverySecret::generate();
        let (foreign, _) = signed_genesis(&[0xBBu8; 32], &other_secret);
        let records = vec![
            vec![0xde, 0xad, 0xbe, 0xef],
            to_canonical_cbor(&foreign).unwrap(),
            to_canonical_cbor(&genesis).unwrap(),
        ];
        let found = find_genesis_record(&records, &vault_id, &recovery_pk).unwrap();
        assert_eq!(found.vault_id, vault_id.to_vec());
        assert_eq!(found.creation_nonce, vec![1u8; 32]);
    }

    #[test]
    fn rejects_wrong_key_bad_sig_and_absence() {
        let vault_id = [0xAAu8; 32];
        let secret = RecoverySecret::generate();
        let (genesis, _) = signed_genesis(&vault_id, &secret);
        let genesis_bytes = to_canonical_cbor(&genesis).unwrap();
        // Wrong recovery key: a validly signed genesis for another root.
        let wrong_pk = RecoverySecret::generate()
            .derive_recovery_signing_key()
            .unwrap()
            .verifying_key()
            .to_bytes();
        assert!(find_genesis_record(&[genesis_bytes], &vault_id, &wrong_pk).is_none());
        // Tampered signature fails closed.
        let mut tampered = genesis.clone();
        tampered.signature = vec![0u8; 64];
        let tampered_bytes = to_canonical_cbor(&tampered).unwrap();
        let (_, recovery_pk) = signed_genesis(&vault_id, &secret);
        assert!(find_genesis_record(&[tampered_bytes], &vault_id, &recovery_pk).is_none());
        // No genesis at all (vault never pushed recovery records).
        assert!(find_genesis_record(&[vec![1, 2, 3]], &vault_id, &recovery_pk).is_none());
    }
}
