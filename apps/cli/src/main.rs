use anyhow::{bail, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};

use ciphervault_crypto::{generate_signing_key, RecoverySecret, VaultEpochKey};
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, ChunkWireObject, DeviceCertificate, GenesisRecord,
    HeadRecord, SnapshotManifest, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_recovery::OfflineRecoveryKit;
use ciphervault_snapshot::{create_snapshot, restore_snapshot};
use ciphervault_storage::{MultiOperatorPool, OperatorClient};

const VAULT_DIR: &str = ".ciphervault";
const DB_FILE: &str = "vault.db";
const RECOVERY_FILE: &str = "recovery_kit_backup.txt";
const OPERATORS_FILE: &str = "operators.json";

#[derive(Parser)]
#[command(name = "ciphervault")]
#[command(author = "CipherVault Team")]
#[command(version = "0.1.0")]
#[command(about = "Decentralized, encrypted version control for confidential files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Initialize a new CipherVault in the current directory
    Init {
        #[arg(short, long, help = "Overwrite existing vault if present")]
        force: bool,

        #[arg(short, long, num_args = 1.., help = "Custom operator endpoints (space separated)")]
        operators: Option<Vec<String>>,
    },

    /// Add confidential files to vault tracking (e.g. .env, keys)
    Track {
        #[arg(required = true, help = "Files to track")]
        paths: Vec<PathBuf>,
    },

    /// Display current vault status and tracked files
    Status,

    /// Create, encrypt, and replicate a snapshot across independent operators
    Push {
        #[arg(short, long, help = "Optional commit message describing this snapshot")]
        message: Option<String>,
    },

    /// Display snapshot history DAG
    History,

    /// Restore confidential files from a snapshot
    Restore {
        #[arg(
            short,
            long,
            help = "Snapshot ID (hex) to restore (defaults to latest head)"
        )]
        snapshot: Option<String>,

        #[arg(
            short,
            long,
            help = "Directory to restore files into (defaults to current directory)"
        )]
        to: Option<PathBuf>,
    },

    /// Recover a vault from an offline recovery kit on a clean machine
    Recover {
        #[arg(
            short,
            long,
            help = "Path to the emergency offline recovery kit text file"
        )]
        kit: PathBuf,

        #[arg(short, long, help = "Directory to restore files into")]
        to: PathBuf,
    },

    /// Emergency offline recovery commands
    Recovery {
        #[command(subcommand)]
        sub: RecoverySubcommand,
    },

    /// Anchor a snapshot head commitment to Arbitrum One
    Anchor {
        #[arg(
            short,
            long,
            help = "Snapshot head CID (hex) to anchor (defaults to active head)"
        )]
        head: Option<String>,

        #[arg(short, long, help = "Arbitrum RPC endpoint URL")]
        rpc: Option<String>,

        #[arg(short, long, help = "Contract address (hex, 20 bytes)")]
        contract: Option<String>,

        #[arg(long, help = "Chain ID (defaults to 42161)")]
        chain_id: Option<u64>,

        #[arg(
            long,
            help = "Confirmed on-chain transaction hash (hex, 32 bytes) if broadcast via external wallet/relayer"
        )]
        tx_hash: Option<String>,
    },

    /// Verify an Arbitrum on-chain commitment and finality stage
    VerifyAnchor {
        #[arg(
            short,
            long,
            help = "Snapshot head CID (hex) to verify (defaults to active head)"
        )]
        head: Option<String>,

        #[arg(short, long, help = "Arbitrum RPC endpoint URL")]
        rpc: Option<String>,
    },

    /// Manage Git pre-commit hooks and secret leak prevention
    Hook {
        #[command(subcommand)]
        sub: HookSubcommand,
    },

    /// Audit ciphertext replica health across independent operators
    Audit {
        #[arg(short, long, num_args = 1.., help = "Custom operator endpoints to audit")]
        operators: Option<Vec<String>>,
    },

    /// Detect and repair degraded replicas across operators
    Repair {
        #[arg(short, long, num_args = 1.., help = "Custom operator endpoints to repair")]
        operators: Option<Vec<String>>,
    },

    /// Launch the local web dashboard and visual vault inspector
    Ui {
        #[arg(long, default_value = "127.0.0.1", help = "Host address to bind to")]
        host: String,

        #[arg(
            short,
            long,
            default_value = "8080",
            help = "Port to serve web dashboard on"
        )]
        port: u16,

        #[arg(long, help = "Do not automatically open default web browser")]
        no_browser: bool,
    },
}

#[derive(Subcommand)]
enum HookSubcommand {
    /// Install Git pre-commit hook into .git/hooks/pre-commit
    Install,

    /// Check for staged confidential files and unbacked modifications
    Check,
}

#[derive(Subcommand)]
enum RecoverySubcommand {
    /// Export or view the offline emergency recovery kit
    Export,

    /// Test clean restore from recovery kit into an isolated folder
    Test {
        #[arg(short, long, help = "Test directory to restore into")]
        to: PathBuf,
    },
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    if let Err(err) = run(cli).await {
        eprintln!("{} {}", "Error:".bold().red(), err);
        std::process::exit(1);
    }
}

async fn run(cli: Cli) -> Result<()> {
    match cli.command {
        Commands::Init { force, operators } => cmd_init(force, operators),
        Commands::Track { paths } => cmd_track(paths),
        Commands::Status => cmd_status(),
        Commands::Push { message } => cmd_push(message).await,
        Commands::History => cmd_history(),
        Commands::Restore { snapshot, to } => cmd_restore(snapshot, to),
        Commands::Recover { kit, to } => cmd_recover(kit, to).await,
        Commands::Recovery { sub } => match sub {
            RecoverySubcommand::Export => cmd_recovery_export(),
            RecoverySubcommand::Test { to } => cmd_recovery_test(to).await,
        },
        Commands::Anchor {
            head,
            rpc,
            contract,
            chain_id,
            tx_hash,
        } => cmd_anchor(head, rpc, contract, chain_id, tx_hash).await,
        Commands::VerifyAnchor { head, rpc } => cmd_verify_anchor(head, rpc).await,
        Commands::Hook { sub } => match sub {
            HookSubcommand::Install => cmd_hook_install(),
            HookSubcommand::Check => cmd_hook_check(),
        },
        Commands::Audit { operators } => cmd_audit(operators).await,
        Commands::Repair { operators } => cmd_repair(operators).await,
        Commands::Ui {
            host,
            port,
            no_browser,
        } => cmd_ui(host, port, no_browser).await,
    }
}

fn get_vault_store() -> Result<LocalVaultStore> {
    let path = Path::new(VAULT_DIR).join(DB_FILE);
    if !path.exists() {
        bail!(
            "No CipherVault found in current directory. Run '{}' first.",
            "ciphervault init".cyan()
        );
    }
    LocalVaultStore::open(path).context("Failed to open local vault database")
}

fn ensure_gitignore() -> Result<()> {
    let gitignore_path = Path::new(".gitignore");
    let entry = "\n# CipherVault local keys, database, and cache\n.ciphervault/\n";

    if gitignore_path.exists() {
        let content = fs::read_to_string(gitignore_path)?;
        if !content.contains(".ciphervault") {
            let mut file = OpenOptions::new().append(true).open(gitignore_path)?;
            file.write_all(entry.as_bytes())?;
        }
    } else {
        fs::write(gitignore_path, entry.trim_start())?;
    }
    Ok(())
}

fn get_configured_operators() -> Vec<String> {
    if let Ok(env_ops) = std::env::var("CIPHERVAULT_OPERATORS") {
        let list: Vec<String> = env_ops
            .split([',', ';', ' '])
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        if !list.is_empty() {
            return list;
        }
    }
    let config_path = Path::new(VAULT_DIR).join(OPERATORS_FILE);
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(ops) = serde_json::from_str::<Vec<String>>(&content) {
                return ops;
            }
        }
    }
    vec![
        "http://127.0.0.1:8201".into(),
        "http://127.0.0.1:8202".into(),
        "http://127.0.0.1:8203".into(),
    ]
}

fn cmd_init(force: bool, custom_operators: Option<Vec<String>>) -> Result<()> {
    let vault_dir = Path::new(VAULT_DIR);
    if vault_dir.exists() && !force {
        bail!("A CipherVault already exists in this directory. Use '--force' to re-initialize.");
    }

    fs::create_dir_all(vault_dir)?;
    ensure_gitignore()?;

    println!("{}", "Initializing new CipherVault...".bold().green());

    let mut vault_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut vault_id);

    let recovery_secret = RecoverySecret::generate();
    let recovery_sk = recovery_secret.derive_recovery_signing_key()?;
    let (_, recovery_enc_pk) = recovery_secret.derive_recovery_encryption_keys()?;

    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: recovery_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: Utc::now().timestamp() as u64,
        creation_nonce: {
            let mut n = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut n);
            n
        },
        signature: Vec::new(),
    };
    genesis.sign(&recovery_sk)?;

    let device_sk = generate_signing_key();
    let mut device_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut device_id);

    let initial_epoch_key = VaultEpochKey::generate();

    let db_path = vault_dir.join(DB_FILE);
    if db_path.exists() {
        fs::remove_file(&db_path)?;
    }
    let store = LocalVaultStore::open(&db_path)?;
    store.init_vault(
        &vault_id,
        &genesis,
        &device_sk,
        &device_id,
        &initial_epoch_key,
    )?;

    // Create, sign, and store device certificate rooted in recovery authority
    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        certificate_id: {
            let mut cid = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut cid);
            cid
        },
        device_signing_pk: device_sk.verifying_key().as_bytes().to_vec(),
        permissions: 0xFFFFFFFF,
        authority_generation: 1,
        issued_at_utc: Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    cert.sign(&recovery_sk)?;
    store.save_device_certificate(&cert)?;

    let operator_endpoints = custom_operators.unwrap_or_else(|| {
        vec![
            "http://127.0.0.1:8101".into(),
            "http://127.0.0.1:8102".into(),
            "http://127.0.0.1:8103".into(),
        ]
    });

    // Save operators config
    let ops_json = serde_json::to_string_pretty(&operator_endpoints)?;
    fs::write(vault_dir.join(OPERATORS_FILE), ops_json)?;

    let kit = OfflineRecoveryKit::create(&vault_id, &recovery_secret, operator_endpoints)?;

    let printable_kit = kit.format_printable();
    let kit_path = vault_dir.join(RECOVERY_FILE);
    fs::write(&kit_path, &printable_kit)?;

    println!(
        "{}",
        "✓ CipherVault initialized successfully!".bold().green()
    );
    println!("  Vault ID:   {}", hex::encode(vault_id).yellow());
    println!("  Device ID:  {}", hex::encode(device_id).cyan());
    println!("  Local DB:   {}", db_path.display());
    println!("  Gitignore:  Updated to ignore '{}'", VAULT_DIR);
    println!();
    println!(
        "{}",
        "================================================================================".yellow()
    );
    println!(
        "{}",
        "                  CRITICAL: SAVE YOUR EMERGENCY RECOVERY KIT                    "
            .bold()
            .yellow()
    );
    println!(
        "{}",
        "================================================================================".yellow()
    );
    println!("{}", printable_kit);
    println!(
        "A copy was saved to: {}",
        kit_path.display().to_string().bold()
    );
    println!(
        "{}",
        "Please print or store this kit in TWO physically separate, secure locations!"
            .bold()
            .red()
    );
    println!("Delete the local plain text file once safely backed up.");

    Ok(())
}

fn cmd_track(paths: Vec<PathBuf>) -> Result<()> {
    let store = get_vault_store()?;
    println!("{}", "Tracking confidential files:".bold());

    for path in paths {
        let path_str = path.to_string_lossy();
        let file_id = store.track_file(&path_str)?;
        let exists = path.exists();
        let status_str = if exists {
            "[found]".green()
        } else {
            "[planned (not on disk yet)]".yellow()
        };
        println!(
            "  {} {} {} (ID: {})",
            "+".green(),
            path_str,
            status_str,
            hex::encode(&file_id[0..4]).dimmed()
        );
    }

    println!(
        "\nTracked files registered. Run '{}' to capture and replicate an encrypted snapshot.",
        "ciphervault push".cyan()
    );
    Ok(())
}

fn cmd_status() -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, _, counter, epoch) = store.get_device_state()?;
    let tracked = store.list_tracked_files()?;
    let active_head = store.get_active_head()?;
    let operators = get_configured_operators();

    println!("{}", "CipherVault Status".bold());
    println!("--------------------------------------------------");
    println!("  Vault ID:        {}", hex::encode(vault_id).yellow());
    println!("  Device ID:       {}", hex::encode(device_id).cyan());
    println!("  Current Epoch:   {}", epoch);
    println!("  Device Counter:  {}", counter);

    if let Some(head) = active_head {
        println!(
            "  Active Head:     {}",
            hex::encode(&head.snapshot_id).green()
        );
    } else {
        println!(
            "  Active Head:     {}",
            "None (no snapshots committed yet)".dimmed()
        );
    }

    println!("\nConfigured Operators ({}):", operators.len());
    for op in operators {
        println!("  - {}", op.dimmed());
    }

    println!("\nTracked Confidential Files ({}):", tracked.len());
    if tracked.is_empty() {
        println!(
            "  (None). Use '{}' to track files like .env or keys.",
            "ciphervault track <path>".cyan()
        );
    } else {
        for (rel_path, file_id) in tracked {
            let exists = rel_path.exists();
            let state = if exists {
                let len = fs::metadata(&rel_path)?.len();
                format!("{} bytes", len).green()
            } else {
                "missing on disk".red()
            };
            println!(
                "  - {:<30} [{}] (ID: {})",
                rel_path.display(),
                state,
                hex::encode(&file_id[0..4]).dimmed()
            );
        }
    }

    Ok(())
}

async fn cmd_push(message: Option<String>) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_sk, counter, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;
    let tracked = store.list_tracked_files()?;

    if tracked.is_empty() {
        bail!(
            "No files are tracked. Track files using '{}' before pushing.",
            "ciphervault track <path>".cyan()
        );
    }

    let active_head = store.get_active_head()?;
    let parent_ids = match active_head {
        Some(ref h) => vec![{
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.snapshot_id);
            arr
        }],
        None => Vec::new(),
    };

    println!("{}", "Capturing and encrypting snapshot...".bold());

    let current_dir = std::env::current_dir()?;
    let output = create_snapshot(
        &current_dir,
        &tracked,
        &vault_id,
        epoch,
        &epoch_key,
        parent_ids.clone(),
        &device_id,
        counter + 1,
        1, // authority generation
        &device_sk,
    )?;

    // Store snapshot and chunks in local transactional queue
    store.save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
    store.increment_device_counter()?;

    let kit = OfflineRecoveryKit::parse_from_printable(&fs::read_to_string(
        Path::new(VAULT_DIR).join(RECOVERY_FILE),
    )?)?;
    let recovery_set = store.prepare_recovery_set(&output.record, &kit)?;
    let record_cid = output.record.compute_record_cid()?;

    // Create and sign updated HeadRecord pointing to snapshot-record CID
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: output.record.parent_snapshot_ids.clone(),
        closure_digest: recovery_set.closure.compute_base_closure_digest()?.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: counter + 1,
        signature: Vec::new(),
    };
    head.sign(&device_sk)?;
    store.set_head(&head)?;

    let snapshot_hex = hex::encode(&output.record.snapshot_id);
    println!(
        "{}",
        "✓ Snapshot captured and encrypted locally!".bold().green()
    );
    println!("  Snapshot ID:    {}", snapshot_hex.yellow());
    println!("  Files captured: {}", tracked.len());
    println!("  Plaintext size: {} bytes", output.closure.total_bytes);
    println!("  Chunks created: {}", output.chunks.len());
    if let Some(msg) = message {
        println!("  Message:        \"{}\"", msg);
    }

    // Attempt multi-operator replication
    let operators = get_configured_operators();
    println!(
        "\nReplicating across {} independent operators...",
        operators.len()
    );

    let pool = MultiOperatorPool::new(operators.clone());

    let wire_objects = store.recovery_objects(&recovery_set)?;
    let head_cbor = to_canonical_cbor(&head)?;
    let closure_digest = recovery_set.closure.compute_base_closure_digest()?;
    let rep_result = pool
        .replicate_and_verify(
            &vault_id,
            &device_sk,
            &wire_objects,
            &closure_digest,
            output.closure.total_bytes,
            90, // 90-day retention
            &recovery_set.locator,
            &head_cbor,
            &recovery_set.records,
            3, // Require a complete recovery set on three operators
        )
        .await;

    match rep_result {
        Ok(receipts) => {
            if receipts.len() >= 3 {
                println!(
                    "  Durability:     {} ({}/{} independent replicas verified and read back)",
                    "RemoteDurable".green().bold(),
                    receipts.len(),
                    operators.len()
                );
            } else {
                println!(
                    "  Durability:     {} ({}/{} replicas verified; degraded)",
                    "Degraded".yellow().bold(),
                    receipts.len(),
                    operators.len()
                );
            }
        }
        Err(e) => {
            println!(
                "  Durability:     {} (Remote upload failed: {})",
                "Local only".yellow().bold(),
                e
            );
            return Err(e.into());
        }
    }

    Ok(())
}

fn cmd_history() -> Result<()> {
    let store = get_vault_store()?;
    let snapshots = store.list_snapshots()?;

    println!("{}", "CipherVault Snapshot History".bold());
    println!("--------------------------------------------------------------------------------");

    if snapshots.is_empty() {
        println!("No snapshots found.");
        return Ok(());
    }

    for (i, snap) in snapshots.iter().enumerate() {
        let snap_hex = hex::encode(&snap.snapshot_id);
        let time_str = Utc
            .timestamp_opt(snap.advisory_timestamp_utc as i64, 0)
            .single()
            .map(|dt| dt.format("%Y-%m-%d %H:%M:%S UTC").to_string())
            .unwrap_or_else(|| "Unknown".into());

        println!("[{}] Snapshot: {}", i + 1, snap_hex.yellow().bold());
        println!("    Timestamp:       {}", time_str);
        println!("    Device Counter:  {}", snap.device_counter);
        println!("    Epoch:           {}", snap.epoch);
        println!(
            "    Manifest CID:    {}",
            hex::encode(&snap.encrypted_manifest_cid).dimmed()
        );

        if snap.parent_snapshot_ids.is_empty() {
            println!("    Parents:         (genesis)");
        } else {
            let parents = snap
                .parent_snapshot_ids
                .iter()
                .map(|p| hex::encode(&p[0..4]))
                .collect::<Vec<_>>()
                .join(", ");
            println!("    Parents:         {}", parents);
        }
        println!();
    }

    Ok(())
}

fn cmd_restore(snapshot_hex_opt: Option<String>, to_dir_opt: Option<PathBuf>) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

    let target_dir = to_dir_opt.unwrap_or_else(|| PathBuf::from("."));

    let snapshot_id = match snapshot_hex_opt {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != 32 {
                bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("No active head snapshot found to restore")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    println!(
        "Restoring snapshot {} into '{}'...",
        hex::encode(snapshot_id).yellow(),
        target_dir.display()
    );

    let (record, encrypted_manifest) = store.get_snapshot(&snapshot_id)?;

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

    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cid_bytes);
            needed_cids.push(arr);
        }
    }

    let chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        bail!(
            "Missing chunks in local store (required {}, found {})",
            needed_cids.len(),
            chunks.len()
        );
    }

    let restored = restore_snapshot(
        &target_dir,
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;

    println!(
        "{}",
        "✓ Snapshot restored and verified successfully!"
            .bold()
            .green()
    );
    for p in restored {
        println!("  - Restored: {}", p.display().to_string().cyan());
    }

    Ok(())
}

async fn cmd_recover(kit_path: PathBuf, to_dir: PathBuf) -> Result<()> {
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
    println!(
        "Loading recovery kit from: {}",
        kit_path.display().to_string().bold()
    );

    if !kit_path.exists() {
        bail!("Recovery kit file does not exist: {}", kit_path.display());
    }

    let kit_text = fs::read_to_string(&kit_path)?;
    let kit = OfflineRecoveryKit::parse_from_printable(&kit_text)?;

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
    let pool = MultiOperatorPool::new(kit.operator_endpoints.clone());

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

fn cmd_recovery_export() -> Result<()> {
    let kit_path = Path::new(VAULT_DIR).join(RECOVERY_FILE);
    if !kit_path.exists() {
        bail!(
            "Recovery kit backup file '{}' not found.",
            kit_path.display()
        );
    }
    let content = fs::read_to_string(kit_path)?;
    println!("{}", content);
    Ok(())
}

async fn cmd_recovery_test(target_dir: PathBuf) -> Result<()> {
    println!(
        "Running offline clean-machine recovery test into '{}'...",
        target_dir.display()
    );
    let kit_path = Path::new(VAULT_DIR).join(RECOVERY_FILE);
    if !kit_path.exists() {
        bail!(
            "Emergency recovery kit not found at '{}'. Run 'ciphervault init' first.",
            kit_path.display()
        );
    }
    cmd_recover(kit_path, target_dir).await
}

async fn cmd_anchor(
    head_hex_opt: Option<String>,
    rpc_opt: Option<String>,
    contract_opt: Option<String>,
    chain_id_opt: Option<u64>,
    tx_hash_opt: Option<String>,
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

    let current_chain_block = client.get_block_number().await.context(format!(
        "Failed to query current block from Arbitrum RPC at '{}'. Please check network connectivity or provide a valid RPC endpoint.",
        rpc_url
    ))?;

    let (block_num, tx_hash, finality_msg) = if let Some(tx_hex) = tx_hash_opt {
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

async fn cmd_verify_anchor(head_hex_opt: Option<String>, rpc_opt: Option<String>) -> Result<()> {
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

    let stage_str = match report.finality_stage {
        ciphervault_storage::AnchorFinalityStage::Pending => "Pending".yellow(),
        ciphervault_storage::AnchorFinalityStage::SequencerConfirmed { block_number } => {
            format!("Sequencer Confirmed (L2 block {})", block_number).green()
        }
        ciphervault_storage::AnchorFinalityStage::ParentDataFinalized { block_number } => format!(
            "Parent Data Finalized on Ethereum L1 (L2 block {})",
            block_number
        )
        .green()
        .bold(),
        ciphervault_storage::AnchorFinalityStage::AssertionSettled { block_number } => format!(
            "Assertion Settled (L2 block {}, 7-day challenge period passed)",
            block_number
        )
        .green()
        .bold(),
    };
    println!("  Finality Stage:    {}", stage_str);

    Ok(())
}

fn cmd_hook_install() -> Result<()> {
    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        bail!("No .git directory found. Ensure you are in the root of a Git repository.");
    }
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    let pre_commit_path = hooks_dir.join("pre-commit");

    let script = r#"#!/bin/sh
# CipherVault pre-commit hook: secret leak prevention & modification checks
ciphervault hook check
"#;

    fs::write(&pre_commit_path, script)?;

    println!(
        "{}",
        "✓ Installed CipherVault pre-commit hook into .git/hooks/pre-commit"
            .green()
            .bold()
    );
    println!(
        "CipherVault will now inspect Git staging before every commit to prevent secret leaks."
    );
    Ok(())
}

fn cmd_hook_check() -> Result<()> {
    let store = get_vault_store()?;
    let tracked = store.list_tracked_files()?;

    // 1. Check staged files via git
    let output = std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .output();

    if let Ok(out) = output {
        let staged_text = String::from_utf8_lossy(&out.stdout);
        let staged_files: Vec<&str> = staged_text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        for (rel_path, _) in &tracked {
            let path_str = rel_path.to_string_lossy().replace('\\', "/");
            if staged_files.iter().any(|s| *s == path_str) {
                eprintln!();
                eprintln!("{}", "================================================================================".red());
                eprintln!("{}", "        [CRITICAL SECURITY ALERT] CIPHERVAULT SECRET STAGED IN GIT              ".bold().red());
                eprintln!("{}", "================================================================================".red());
                eprintln!(
                    "Tracked confidential file '{}' is currently staged for commit in Git!",
                    path_str.yellow().bold()
                );
                eprintln!(
                    "Plaintext secrets must NEVER be committed to Git version control history."
                );
                eprintln!();
                eprintln!("To unstage this secret immediately, run:");
                eprintln!("  {}", format!("git reset HEAD {}", path_str).cyan().bold());
                eprintln!();
                eprintln!(
                    "CipherVault snapshots protect this file independently without Git tracking."
                );
                eprintln!("{}", "================================================================================".red());
                std::process::exit(1);
            }
        }
    }

    println!("✓ CipherVault pre-commit check: No confidential secrets staged in Git.");
    Ok(())
}

async fn audit_current(
    custom_operators: Option<Vec<String>>,
) -> Result<ciphervault_maintenance::engine::RecoveryAudit> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let head = store.get_active_head()?.context("No snapshot to audit")?;
    let cid: [u8; 32] = head
        .snapshot_id
        .as_slice()
        .try_into()
        .context("Invalid head CID")?;
    let set = store
        .get_recovery_set(&cid)
        .context("No recovery inventory; create a new snapshot")?;
    anyhow::ensure!(
        set.closure.compute_base_closure_digest()?.as_slice() == head.closure_digest,
        "Recovery inventory does not match signed head"
    );
    let engine = ciphervault_maintenance::MaintenanceEngine::new(
        custom_operators.unwrap_or_else(get_configured_operators),
    );
    let sessions = engine.authenticate_all(&vault_id, &device_sk).await;
    engine
        .audit_recovery_set(&set, &to_canonical_cbor(&head)?, &sessions)
        .await
}

async fn cmd_audit(custom_operators: Option<Vec<String>>) -> Result<()> {
    let report = audit_current(custom_operators).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    anyhow::ensure!(report.healthy, "Recovery set is not durable: {} complete replicas, {} lost objects, {} missing discovery logs",
        report.recoverable_operators.len(), report.objects.lost_count, report.discovery_missing.len());
    Ok(())
}

async fn cmd_repair(custom_operators: Option<Vec<String>>) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let active_head = store
        .get_active_head()?
        .context("No active head snapshot found to repair")?;

    let operators = custom_operators.unwrap_or_else(get_configured_operators);
    println!(
        "{}",
        "Auditing and repairing degraded replicas across operators...".bold()
    );

    let engine = ciphervault_maintenance::MaintenanceEngine::new(operators.clone());
    let sessions = engine.authenticate_all(&vault_id, &device_sk).await;

    let mut head_snap_id = [0u8; 32];
    head_snap_id.copy_from_slice(&active_head.snapshot_id);

    let recovery_set = store.get_recovery_set(&head_snap_id).context("Snapshot has no complete recovery inventory; create a new snapshot before auditing or repairing")?;
    let closure = recovery_set.closure.clone();
    let audit = engine.audit_closure(&closure, &sessions).await?;
    let objects = store.recovery_objects(&recovery_set)?;
    let head_bytes = to_canonical_cbor(&active_head)?;
    // Local verified ciphertext can also repair a total remote loss.
    MultiOperatorPool::new(operators)
        .replicate_and_verify(
            &vault_id,
            &device_sk,
            &objects,
            &closure.compute_base_closure_digest()?,
            closure.total_bytes,
            90,
            &recovery_set.locator,
            &head_bytes,
            &recovery_set.records,
            3,
        )
        .await?;
    println!("Repair completed: complete recovery set read back on three operators ({} previously degraded objects).", audit.degraded_objects.len());

    Ok(())
}

const UI_INDEX_HTML: &str = include_str!("../../ui/index.html");
const UI_STYLES_CSS: &str = include_str!("../../ui/styles.css");
const UI_APP_JS: &str = include_str!("../../ui/app.js");

async fn cmd_ui(host: String, port: u16, no_browser: bool) -> Result<()> {
    use axum::{http::header, response::Html, routing::get, Router};

    let app = Router::new()
        .route("/", get(|| async { Html(UI_INDEX_HTML) }))
        .route(
            "/styles.css",
            get(|| async { ([(header::CONTENT_TYPE, "text/css")], UI_STYLES_CSS) }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "application/javascript")],
                    UI_APP_JS,
                )
            }),
        )
        .route("/api/vault", get(api_vault_handler))
        .route("/api/operators", get(api_operators_handler))
        .route(
            "/api/snapshots",
            get(api_snapshots_handler).post(api_create_snapshot_handler),
        )
        .route(
            "/api/anchors",
            get(api_anchors_handler).post(api_create_anchor_handler),
        )
        .route("/api/audit", get(api_audit_handler).post(api_audit_handler));

    let host_ip: std::net::IpAddr = host
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)));
    let addr = std::net::SocketAddr::new(host_ip, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Web Dashboard & Vault Inspector"
            .bold()
            .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "  Dashboard URL:  {}",
        format!("http://{}:{}", host, port).bold().yellow()
    );
    println!("  Serving Mode:   Self-Contained Embedded UI");
    println!("  Press Ctrl+C to stop server.\n");

    if !no_browser {
        let url = format!("http://127.0.0.1:{}", port);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            #[cfg(target_os = "windows")]
            {
                let _ = std::process::Command::new("powershell")
                    .args(["-Command", &format!("Start-Process '{}'", url)])
                    .spawn();
            }
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}

async fn api_vault_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "initialized": false,
                "message": "No vault initialized in current directory"
            }));
        }
    };

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);
    let (device_id, _signing_key, device_counter, epoch) =
        store
            .get_device_state()
            .unwrap_or(([0u8; 32], generate_signing_key(), 0, 1));
    let tracked = store.list_tracked_files().unwrap_or_default();
    let operators = get_configured_operators();

    let mut recovery_info = serde_json::json!(null);
    let recovery_path = Path::new(VAULT_DIR).join(RECOVERY_FILE);
    if recovery_path.exists() {
        if let Ok(content) = fs::read_to_string(&recovery_path) {
            let mut signing_pk = String::new();
            let mut encrypt_pk = String::new();
            let mut locator = String::new();
            let mut crc32 = String::new();

            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("Recovery Signing PK:") {
                    signing_pk = rest.trim().to_string();
                } else if let Some(rest) = trimmed.strip_prefix("Recovery Encrypt PK:") {
                    encrypt_pk = rest.trim().to_string();
                } else if let Some(rest) = trimmed.strip_prefix("Recovery Locator:") {
                    locator = rest.trim().to_string();
                } else if let Some(rest) = trimmed.strip_prefix("Checksum (CRC32):") {
                    crc32 = rest.trim().to_string();
                }
            }

            recovery_info = serde_json::json!({
                "available": true,
                "recovery_signing_pk_hex": signing_pk,
                "recovery_encrypt_pk_hex": encrypt_pk,
                "recovery_locator_hex": locator,
                "crc32": crc32,
            });
        }
    }

    axum::Json(serde_json::json!({
        "initialized": true,
        "vault_id_hex": hex::encode(vault_id),
        "device_id_hex": hex::encode(device_id),
        "device_counter": device_counter,
        "epoch": epoch,
        "tracked_files": tracked.iter().map(|(p, id)| {
            let full_path = Path::new(p);
            let size_bytes = fs::metadata(full_path).map(|m| m.len()).unwrap_or(0);
            serde_json::json!({
                "path": p.to_string_lossy(),
                "file_id_hex": hex::encode(id),
                "size_bytes": size_bytes,
                "chunks_count": (size_bytes as usize / (1024 * 1024)) + 1,
            })
        }).collect::<Vec<_>>(),
        "operators": operators,
        "recovery": recovery_info,
    }))
}

async fn api_operators_handler() -> impl axum::response::IntoResponse {
    let operators = get_configured_operators();
    let mut results = Vec::new();

    for endpoint in operators {
        let client = OperatorClient::new(endpoint.clone());
        let start = std::time::Instant::now();
        match client.get_info().await {
            Ok(info) => {
                let latency_ms = start.elapsed().as_millis();
                let safe_pk = if info.operator_signing_pk_hex.len() == 64
                    && info
                        .operator_signing_pk_hex
                        .chars()
                        .all(|c| c.is_ascii_hexdigit())
                {
                    info.operator_signing_pk_hex
                } else {
                    "INVALID_KEY_FORMAT".to_string()
                };
                let safe_id = info
                    .operator_id
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
                    .collect::<String>();
                results.push(serde_json::json!({
                    "endpoint": endpoint,
                    "status": "online",
                    "operator_id": safe_id,
                    "operator_signing_pk_hex": safe_pk,
                    "latency_ms": latency_ms,
                    "retention_terms": info.retention_terms,
                }));
            }
            Err(e) => {
                results.push(serde_json::json!({
                    "endpoint": endpoint,
                    "status": "offline",
                    "error": e.to_string(),
                }));
            }
        }
    }

    axum::Json(serde_json::json!(results))
}

async fn api_snapshots_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => return axum::Json(serde_json::json!([])),
    };

    let snapshots = store.list_snapshots().unwrap_or_default();
    let active_head = store.get_active_head().ok().flatten();

    let json_snaps: Vec<_> = snapshots.iter().map(|snap| {
        let record_cid = snap.compute_record_cid().ok();
        let is_head = active_head.as_ref().map(|h| {
            h.snapshot_id == snap.snapshot_id || record_cid.as_ref().map(|rc| rc.as_slice() == h.snapshot_id.as_slice()).unwrap_or(false)
        }).unwrap_or(false);
        serde_json::json!({
            "snapshot_id_hex": hex::encode(&snap.snapshot_id),
            "parent_ids_hex": snap.parent_snapshot_ids.iter().map(hex::encode).collect::<Vec<_>>(),
            "manifest_cid_hex": hex::encode(&snap.encrypted_manifest_cid),
            "device_id_hex": hex::encode(&snap.device_id),
            "device_counter": snap.device_counter,
            "epoch": snap.epoch,
            "timestamp_utc": snap.advisory_timestamp_utc,
            "is_head": is_head,
        })
    }).collect();

    axum::Json(serde_json::json!(json_snaps))
}

async fn api_anchors_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => return axum::Json(serde_json::json!([])),
    };

    let anchors = store.list_checkpoint_evidence().unwrap_or_default();
    let json_anchors: Vec<_> = anchors
        .iter()
        .map(|ev| {
            serde_json::json!({
                "commitment_hex": hex::encode(&ev.commitment),
                "salt_hex": hex::encode(&ev.salt),
                "head_record_cid_hex": hex::encode(&ev.head_record_cid),
                "chain_id": ev.chain_id,
                "contract_address_hex": format!("0x{}", hex::encode(&ev.contract_address)),
                "tx_hash_hex": format!("0x{}", hex::encode(&ev.tx_hash)),
                "block_number": ev.block_number,
                "timestamp_utc": ev.timestamp_utc,
            })
        })
        .collect();

    axum::Json(serde_json::json!(json_anchors))
}

#[derive(serde::Deserialize)]
struct CreateSnapshotRequest {
    message: Option<String>,
}

async fn api_create_snapshot_handler(
    axum::Json(payload): axum::Json<CreateSnapshotRequest>,
) -> impl axum::response::IntoResponse {
    match cmd_push(payload.message).await {
        Ok(_) => {
            let store_res = get_vault_store();
            let snap_id = if let Ok(store) = store_res {
                if let Ok(Some(head)) = store.get_active_head() {
                    hex::encode(&head.snapshot_id)
                } else {
                    String::new()
                }
            } else {
                String::new()
            };
            axum::Json(serde_json::json!({
                "success": true,
                "snapshot_id_hex": snap_id,
                "message": "Snapshot successfully captured, encrypted, and replicated across operators"
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_create_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "success": true,
            "message": "Snapshot head commitment successfully prepared and recorded for Arbitrum One"
        })),
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_audit_handler() -> impl axum::response::IntoResponse {
    match audit_current(None).await {
        Ok(report) => axum::Json(
            serde_json::json!({ "success": report.healthy, "report": report,
            "message": if report.healthy { "Complete recovery set verified on at least three operators" } else { "Recovery set degraded or incomplete; inspect audit report" } }),
        ),
        Err(e) => axum::Json(serde_json::json!({"success": false, "error": e.to_string()})),
    }
}
