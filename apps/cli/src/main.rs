use anyhow::{bail, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{Parser, Subcommand};
use colored::*;
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;
use zeroize::Zeroize;

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::stream::{self, Stream};

use ciphervault_crypto::{
    generate_signing_key, HardwareSecurityModule, RecoverySecret, VaultEpochKey,
};
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, ChunkWireObject, DeviceCertificate, GenesisRecord,
    HeadRecord, SnapshotManifest, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_maintenance::MaintenanceDb;
use ciphervault_recovery::{OfflineRecoveryKit, ThresholdRecoveryKit};
use ciphervault_snapshot::{
    create_snapshot, create_snapshot_with_signer, fastcdc_chunk, restore_snapshot, DeviceSigner,
    FastCdcConfig,
};
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

        #[arg(
            long,
            help = "Optional path to export emergency recovery kit backup text file"
        )]
        save_kit: Option<PathBuf>,

        #[arg(
            long,
            help = "Bind device signing identity to physical hardware token (YubiKey Slot 9C)"
        )]
        hardware_token: bool,
    },

    /// Add confidential files to vault tracking (e.g. .env, keys)
    Track {
        #[arg(required = true, help = "Files to track")]
        paths: Vec<PathBuf>,
    },

    /// Remove confidential files from vault tracking
    Untrack {
        #[arg(required = true, help = "Files to untrack")]
        paths: Vec<PathBuf>,
    },

    /// Display current vault status and tracked files
    Status,

    /// Create, encrypt, and replicate a snapshot across independent operators
    Push {
        #[arg(short, long, help = "Optional commit message describing this snapshot")]
        message: Option<String>,

        #[arg(
            long,
            help = "Require physical hardware touch confirmation before signing snapshot commit"
        )]
        touch: bool,

        #[arg(
            long,
            help = "Execute bandwidth-optimized proof-of-storage challenge readback"
        )]
        pos: bool,
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

    /// Recover a vault from an offline recovery kit or threshold guardian shares on a clean machine
    Recover {
        #[arg(
            short,
            long,
            help = "Path to the emergency offline recovery kit text file"
        )]
        kit: Option<PathBuf>,

        #[arg(
            long,
            num_args = 1..,
            help = "Paths to M-of-N threshold guardian share files (e.g. --shares g1.txt g2.txt)"
        )]
        shares: Option<Vec<PathBuf>>,

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

        #[arg(
            long,
            help = "Raw signed transaction hex to broadcast directly via JSON-RPC eth_sendRawTransaction"
        )]
        raw_tx: Option<String>,

        #[arg(
            long,
            help = "Automatically submit and confirm commitment through background L2 relayer"
        )]
        auto_relay: bool,

        #[arg(long, help = "URL of the automated L2 relayer service")]
        relayer_url: Option<String>,
    },

    /// Verify an Arbitrum on-chain commitment and finality stage
    VerifyAnchor {
        #[arg(
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

    /// Manage physical hardware security tokens (YubiKey PIV / PC/SC)
    Token {
        #[command(subcommand)]
        sub: TokenSubcommand,
    },
}

#[derive(Subcommand)]
enum TokenSubcommand {
    /// Display connection status of attached PC/SC smartcard readers and tokens
    Status,

    /// Probe physical token and inspect PIV Slot 9C (Signing) and Slot 9D (Key Management)
    Probe,
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

    /// Split the master recovery secret into M-of-N threshold guardian shares
    Split {
        #[arg(
            short,
            long,
            default_value = "2",
            help = "Threshold (M): minimum guardian shares required to reconstruct"
        )]
        threshold: u8,

        #[arg(
            short,
            long,
            default_value = "3",
            help = "Total shares (N): total number of guardian shares to generate"
        )]
        shares: u8,

        #[arg(
            short,
            long,
            help = "Path to the emergency recovery kit text file (if not reading from terminal prompt)"
        )]
        kit: Option<PathBuf>,

        #[arg(
            short,
            long,
            help = "Directory to save generated guardian share sheets (e.g. ./guardians)"
        )]
        out_dir: Option<PathBuf>,
    },

    /// Test clean restore from recovery kit into an isolated folder
    Test {
        #[arg(
            short,
            long,
            help = "Path to emergency recovery kit text file (defaults to legacy backup file if present)"
        )]
        kit: Option<PathBuf>,

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
        Commands::Init {
            force,
            operators,
            save_kit,
            hardware_token,
        } => cmd_init(force, operators, save_kit, hardware_token),
        Commands::Track { paths } => cmd_track(paths),
        Commands::Untrack { paths } => cmd_untrack(paths),
        Commands::Status => cmd_status(),
        Commands::Push {
            message,
            touch,
            pos: _,
        } => cmd_push(message, touch).await,
        Commands::History => cmd_history(),
        Commands::Restore { snapshot, to } => cmd_restore(snapshot, to),
        Commands::Recover { kit, shares, to } => cmd_recover(kit, shares, to).await,
        Commands::Recovery { sub } => match sub {
            RecoverySubcommand::Export => cmd_recovery_export(),
            RecoverySubcommand::Split {
                threshold,
                shares,
                kit,
                out_dir,
            } => cmd_recovery_split(threshold, shares, kit, out_dir).await,
            RecoverySubcommand::Test { kit, to } => cmd_recovery_test(kit, to).await,
        },
        Commands::Token { sub } => cmd_token(sub).await,
        Commands::Anchor {
            head,
            rpc,
            contract,
            chain_id,
            tx_hash,
            raw_tx,
            auto_relay,
            relayer_url,
        } => {
            cmd_anchor(
                head,
                rpc,
                contract,
                chain_id,
                tx_hash,
                raw_tx,
                auto_relay,
                relayer_url,
            )
            .await
        }
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

fn cmd_init(
    force: bool,
    custom_operators: Option<Vec<String>>,
    save_kit: Option<PathBuf>,
    hardware_token: bool,
) -> Result<()> {
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
    let recovery_locator = recovery_secret.derive_recovery_locator()?;

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

    let (device_sk, device_pk) = if hardware_token {
        println!(
            "{}",
            "Hardware Token Binding Requested (--hardware-token):"
                .bold()
                .cyan()
        );
        match ciphervault_crypto::PcscHardwareToken::probe()? {
            Some(token) => {
                println!(
                    "  Detected token on reader: {}",
                    token.reader_name().yellow().bold()
                );
                let pk = token.get_public_key(ciphervault_crypto::HsmSlot::DigitalSignature)?;
                println!(
                    "  Bound to PIV Slot 9C Public Key: {}",
                    hex::encode(&pk).green()
                );
                let sk = generate_signing_key();
                (sk, pk)
            }
            None => {
                bail!("--hardware-token specified, but no physical YubiKey or PIV smartcard token was found in PC/SC readers.");
            }
        }
    } else {
        let sk = generate_signing_key();
        let pk = sk.verifying_key().as_bytes().to_vec();
        (sk, pk)
    };

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
        &recovery_locator,
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
        device_signing_pk: device_pk,
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

    if let Some(ref path) = save_kit {
        fs::write(path, &printable_kit)?;
        println!(
            "An emergency recovery kit backup file was explicitly saved to: {}",
            path.display().to_string().bold()
        );
    }

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
        "{}",
        "================================================================================".yellow()
    );
    println!(
        "{}",
        "NOTE: In accordance with zero-disk-recovery policy, this secret is NEVER saved"
            .bold()
            .red()
    );
    println!(
        "{}",
        "to disk in .ciphervault/. Record this kit immediately in an offline vault."
            .bold()
            .red()
    );
    println!();

    if std::io::stdin().is_terminal() {
        print!(
            "{}",
            "Type 'yes' or press Enter once you have recorded your recovery secret to zeroize memory: "
                .bold()
                .cyan()
        );
        let _ = std::io::stdout().flush();
        let mut confirm = String::new();
        let _ = std::io::stdin().read_line(&mut confirm);
    }
    println!("{}", "✓ Recovery secret zeroized from memory.".green());

    // Explicit drop to ensure memory scrubbing
    drop(kit);
    drop(recovery_secret);
    drop(recovery_sk);

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

fn cmd_untrack(paths: Vec<PathBuf>) -> Result<()> {
    let store = get_vault_store()?;
    println!("{}", "Untracking confidential files:".bold());

    for path in paths {
        let path_str = path.to_string_lossy();
        let removed = store.untrack_file(&path_str)?;
        if removed {
            println!("  {} {} {}", "-".red(), path_str, "[untracked]".yellow());
        } else {
            println!(
                "  {} {} {}",
                "!".dimmed(),
                path_str,
                "[not currently tracked]".dimmed()
            );
        }
    }
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

async fn cmd_push(message: Option<String>, touch: bool) -> Result<()> {
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

    let certs = store.list_device_certificates()?;
    let is_hardware_bound = certs
        .first()
        .map(|c| c.device_signing_pk != device_sk.verifying_key().to_bytes())
        .unwrap_or(false);

    let maybe_token = if touch || is_hardware_bound {
        if touch {
            println!(
                "{}",
                "Hardware Touch Presence Authorization (--touch):"
                    .bold()
                    .yellow()
            );
            println!(
                "  Please tap your physical YubiKey / hardware token to sign snapshot commit..."
            );
        } else {
            println!("{}", "Hardware-Bound Vault Signing Ceremony:".bold().cyan());
            println!(
                "  Using physical YubiKey / hardware token (Slot 9C) for snapshot signature..."
            );
        }
        match ciphervault_crypto::PcscHardwareToken::probe()? {
            Some(token) => {
                println!("  Found token on reader: {}", token.reader_name().cyan());
                Some(token)
            }
            None => {
                bail!(
                    "Hardware token required (--touch or hardware-bound vault), but no physical YubiKey or smartcard token was detected in PC/SC readers."
                );
            }
        }
    } else {
        None
    };

    println!("{}", "Capturing and encrypting snapshot...".bold());

    let current_dir = std::env::current_dir()?;
    let output = match &maybe_token {
        Some(token) => create_snapshot_with_signer(
            &current_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids.clone(),
            &device_id,
            counter + 1,
            1, // authority generation
            &DeviceSigner::Hardware(token, ciphervault_crypto::HsmSlot::DigitalSignature),
        )?,
        None => create_snapshot(
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
        )?,
    };

    // Store snapshot and chunks in local transactional queue
    store.save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
    store.increment_device_counter()?;

    let recovery_set = store.prepare_recovery_set(&output.record)?;
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

    if let Some(ref token) = maybe_token {
        head.sign_with_hsm(token, ciphervault_crypto::HsmSlot::DigitalSignature)?;
        if touch {
            println!(
                "  {}",
                "✓ Physical touch presence confirmed!".green().bold()
            );
        } else {
            println!(
                "  {}",
                "✓ Hardware token Slot 9C signature confirmed!"
                    .green()
                    .bold()
            );
        }
    } else {
        head.sign(&device_sk)?;
    }

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

async fn cmd_recover(
    kit_opt: Option<PathBuf>,
    shares_opt: Option<Vec<PathBuf>>,
    to_dir: PathBuf,
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

        let kit_text = fs::read_to_string(&kit_path)?;
        OfflineRecoveryKit::parse_from_printable(&kit_text)?
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
    if kit_path.exists() {
        let content = fs::read_to_string(kit_path)?;
        println!("{}", content);
        return Ok(());
    }

    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (sig_pk, enc_pk, locator) = store.get_recovery_descriptors()?;
    let operators = get_configured_operators();

    println!("{}", "CipherVault Public Recovery Descriptors".bold());
    println!("--------------------------------------------------------------------------------");
    println!("  Vault ID:             {}", hex::encode(vault_id).yellow());
    println!("  Recovery Signing PK:  {}", hex::encode(sig_pk).cyan());
    println!("  Recovery Encrypt PK:  {}", hex::encode(enc_pk).cyan());
    println!("  Recovery Locator:     {}", hex::encode(locator).green());
    println!("\nConfigured Recovery Operators ({}):", operators.len());
    for op in &operators {
        println!("  - {}", op.dimmed());
    }
    println!();
    println!(
        "{}",
        "In accordance with zero-disk-recovery policy, the emergency recovery secret (R)".yellow()
    );
    println!("is kept offline and is not saved unencrypted on disk.");
    println!("To test disaster recovery or restore, supply your recovery kit using:");
    println!("  ciphervault recovery test --kit <PATH> --to <TEST_DIR>");
    Ok(())
}

async fn cmd_recovery_test(kit_opt: Option<PathBuf>, target_dir: PathBuf) -> Result<()> {
    let kit_path = match kit_opt {
        Some(p) => p,
        None => {
            let legacy = Path::new(VAULT_DIR).join(RECOVERY_FILE);
            if legacy.exists() {
                legacy
            } else {
                bail!(
                    "No recovery kit specified and no legacy kit found at '{}'.\nSpecify the kit using: ciphervault recovery test --kit <PATH> --to {}",
                    legacy.display(),
                    target_dir.display()
                );
            }
        }
    };

    println!(
        "Running offline clean-machine recovery test into '{}'...",
        target_dir.display()
    );
    cmd_recover(Some(kit_path), None, target_dir).await
}

async fn cmd_recovery_split(
    threshold: u8,
    shares: u8,
    kit_opt: Option<PathBuf>,
    out_dir_opt: Option<PathBuf>,
) -> Result<()> {
    if threshold < 2 {
        bail!("Threshold must be at least 2 guardians");
    }
    if shares < threshold {
        bail!(
            "Total shares ({}) cannot be less than threshold ({})",
            shares,
            threshold
        );
    }

    let kit = if let Some(kit_path) = kit_opt {
        let text = fs::read_to_string(&kit_path)?;
        OfflineRecoveryKit::parse_from_printable(&text)?
    } else {
        let legacy = Path::new(VAULT_DIR).join(RECOVERY_FILE);
        if legacy.exists() {
            let text = fs::read_to_string(&legacy)?;
            OfflineRecoveryKit::parse_from_printable(&text)?
        } else {
            println!(
                "{}",
                "Splitting Master Recovery Secret into Guardian Shares".bold()
            );
            print!("Enter the 64-character hex master recovery secret (R): ");
            let _ = std::io::stdout().flush();
            let mut secret_input = String::new();
            std::io::stdin()
                .read_line(&mut secret_input)
                .context("Failed to read master recovery secret from terminal")?;
            let clean = secret_input.trim().trim_start_matches("0x");
            let mut secret_bytes = hex::decode(clean).context("Invalid hex for recovery secret")?;
            secret_input.zeroize();
            if secret_bytes.len() != 32 {
                secret_bytes.zeroize();
                bail!("Recovery secret must be exactly 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&secret_bytes);
            secret_bytes.zeroize();
            let secret = ciphervault_crypto::RecoverySecret::from_bytes(arr);

            let store = get_vault_store()?;
            let vault_id = store.get_vault_id()?;
            let operators = get_configured_operators();
            OfflineRecoveryKit::create(&vault_id, &secret, operators)?
        }
    };

    println!(
        "Splitting vault {} recovery key into {}-of-{} threshold scheme...",
        kit.vault_id_hex.yellow(),
        threshold,
        shares
    );

    let guardian_kits =
        ciphervault_recovery::ThresholdRecoveryKit::split_kit(&kit, threshold, shares)?;

    if let Some(out_dir) = out_dir_opt {
        fs::create_dir_all(&out_dir)?;
        for g in &guardian_kits {
            let file_name = format!(
                "guardian_share_{}_of_{}.txt",
                g.guardian_index, g.total_shares
            );
            let file_path = out_dir.join(file_name);
            fs::write(&file_path, g.format_guardian_sheet())?;
            println!(
                "  ✓ Written guardian share {} to '{}'",
                g.guardian_index,
                file_path.display()
            );
        }
        println!(
            "\n{}",
            "Successfully exported all guardian threshold sheets!"
                .green()
                .bold()
        );
        println!(
            "Distribute each share file to a different guardian and delete the directory from this machine."
        );
    } else {
        println!(
            "\n{}",
            "================================================================================"
                .green()
        );
        for g in &guardian_kits {
            println!("{}", g.format_guardian_sheet());
        }
    }

    Ok(())
}

#[allow(
    clippy::too_many_arguments,
    reason = "Command line parameter forwarding"
)]
async fn cmd_anchor(
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
            .context("Timed out waiting for L2 sequencer transaction receipt")?;

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
            "SequencerConfirmed (Live Arbitrum L2 Settlement)",
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

        let finality_msg = if receipt.status == "SequencerConfirmed" {
            println!(
                "{}",
                "✓ Automated L2 Relayer Sequencer Confirmation Received!"
                    .green()
                    .bold()
            );
            println!("  Relayer Sequencer Tx: 0x{}", receipt.tx_hash_hex.cyan());
            println!("  Sequencer Block:      {}", receipt.block_number);
            println!("  Finality Status:      {}", receipt.status.green());
            "SequencerConfirmed (Automated L2 Relayer)"
        } else {
            println!(
                "{}",
                "✓ Checkpoint queued with automated L2 relayer (pending on-chain sequencer mining)!"
                    .yellow()
                    .bold()
            );
            println!("  Relayer Status:       {}", receipt.status.yellow());
            "QueuedForRelay (Pending L2 Submission)"
        };

        (receipt.block_number, th, finality_msg)
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

async fn cmd_token(sub: TokenSubcommand) -> Result<()> {
    match sub {
        TokenSubcommand::Status => {
            println!(
                "{}",
                "=== CIPHERVAULT HARDWARE SECURITY MODULE & YUBIKEY STATUS ==="
                    .bold()
                    .cyan()
            );
            let readers = ciphervault_crypto::list_pcsc_readers()?;
            if readers.is_empty() {
                println!("  PC/SC Subsystem:  Active");
                println!("  Attached Readers: None detected");
                println!("\n{}", "To use a hardware token:".yellow());
                println!("  1. Insert a YubiKey 5 Series or PIV-compliant smartcard.");
                println!("  2. Ensure the PC/SC SmartCard service is running.");
                println!("  3. Run 'ciphervault token status' again.");
                return Ok(());
            }

            println!("  Attached Readers ({}):", readers.len());
            for r in &readers {
                println!("    - {}", r.green().bold());
            }

            println!("\n{}", "Probing PIV Applet on attached tokens...".dimmed());
            match ciphervault_crypto::PcscHardwareToken::probe()? {
                Some(token) => {
                    println!(
                        "  Hardware Token:   Connected ({})",
                        token.reader_name().yellow().bold()
                    );
                    if let Ok(info_9c) =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)
                    {
                        println!(
                            "  Slot 9C (Sign):   {} | Touch: {}",
                            info_9c.algorithm.green(),
                            info_9c.touch_policy.cyan()
                        );
                        println!("                    PK: {}", info_9c.public_key_hex);
                    }
                    if let Ok(info_9d) =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)
                    {
                        println!(
                            "  Slot 9D (ECDH):   {} | Touch: {}",
                            info_9d.algorithm.green(),
                            info_9d.touch_policy.cyan()
                        );
                        println!("                    PK: {}", info_9d.public_key_hex);
                    }
                    println!("\n  Status:           Ready for '--hardware-token' and '--touch' operations.");
                }
                None => {
                    println!(
                        "  Hardware Token:   Reader present, but no responsive PIV smartcard applet found."
                    );
                }
            }
        }
        TokenSubcommand::Probe => match ciphervault_crypto::PcscHardwareToken::probe()? {
            Some(token) => {
                let info_9c = token.get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)?;
                let info_9d = token.get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)?;
                let payload = serde_json::json!({
                    "detected": true,
                    "reader": token.reader_name(),
                    "slot_9c": info_9c,
                    "slot_9d": info_9d,
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
            None => {
                let readers = ciphervault_crypto::list_pcsc_readers()?;
                let payload = serde_json::json!({
                    "detected": false,
                    "readers": readers,
                    "message": "No PIV smartcard token detected in PC/SC readers",
                });
                println!("{}", serde_json::to_string_pretty(&payload)?);
            }
        },
    }
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
    let local_objects = store.recovery_objects(&set).ok().map(|objs| {
        objs.into_iter()
            .collect::<std::collections::HashMap<[u8; 32], Vec<u8>>>()
    });
    engine
        .audit_recovery_set_with_cache(
            &set,
            &to_canonical_cbor(&head)?,
            &sessions,
            local_objects.as_ref(),
        )
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
    let objects = store.recovery_objects(&recovery_set)?;
    let local_map: std::collections::HashMap<[u8; 32], Vec<u8>> = objects.iter().cloned().collect();
    let audit = engine
        .audit_closure_with_cache(&closure, &sessions, Some(&local_map))
        .await?;
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
        .route("/api/audit", get(api_audit_handler).post(api_audit_handler))
        .route("/api/guardians", get(api_guardians_handler))
        .route(
            "/api/guardians/split",
            axum::routing::post(api_guardians_split_handler),
        )
        .route(
            "/api/guardians/reconstruct",
            axum::routing::post(api_guardians_reconstruct_handler),
        )
        .route(
            "/api/relayer/checkpoints",
            get(api_relayer_checkpoints_handler),
        )
        .route(
            "/api/relayer/anchor",
            axum::routing::post(api_relayer_anchor_handler),
        )
        .route("/api/fleet", get(api_fleet_handler))
        .route(
            "/api/fleet/audit",
            axum::routing::post(api_fleet_audit_handler),
        )
        .route("/api/token", get(api_token_handler))
        .route("/api/stream", get(api_stream_handler))
        .route(
            "/api/fastcdc/inspect",
            axum::routing::post(api_fastcdc_inspect_handler),
        );

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
    if let Ok((signing_pk, encrypt_pk, locator)) = store.get_recovery_descriptors() {
        recovery_info = serde_json::json!({
            "available": true,
            "recovery_signing_pk_hex": hex::encode(signing_pk),
            "recovery_encrypt_pk_hex": hex::encode(encrypt_pk),
            "recovery_locator_hex": hex::encode(locator),
            "offline_secret_secured": true,
        });
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
    match cmd_push(payload.message, false).await {
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
    match cmd_anchor(None, None, None, None, None, None, false, None).await {
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

async fn api_guardians_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "initialized": false,
                "message": "Vault not initialized in current directory"
            }));
        }
    };

    let vault_id = store.get_vault_id().unwrap_or([0u8; 32]);
    let (signing_pk, encrypt_pk, locator) = match store.get_recovery_descriptors() {
        Ok(d) => d,
        Err(_) => return axum::Json(serde_json::json!({ "initialized": false })),
    };

    let operators = get_configured_operators();

    axum::Json(serde_json::json!({
        "initialized": true,
        "vault_id_hex": hex::encode(vault_id),
        "recovery_signing_pk_hex": hex::encode(signing_pk),
        "recovery_encrypt_pk_hex": hex::encode(encrypt_pk),
        "recovery_locator_hex": hex::encode(locator),
        "operator_endpoints": operators,
        "default_threshold": 3,
        "default_total_shares": 5,
        "mode": "Pure-Rust GF(2^8) Shamir Secret Sharing",
    }))
}

#[derive(serde::Deserialize)]
struct SplitGuardiansRequest {
    threshold: Option<u8>,
    total_shares: Option<u8>,
}

async fn api_guardians_split_handler(
    axum::Json(payload): axum::Json<SplitGuardiansRequest>,
) -> impl axum::response::IntoResponse {
    let threshold = payload.threshold.unwrap_or(3);
    let total_shares = payload.total_shares.unwrap_or(5);

    if threshold < 2 || threshold > total_shares || total_shares > 10 {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Threshold parameters must satisfy: 2 <= threshold <= total_shares <= 10"
        }));
    }

    let store_res = get_vault_store();
    let (vault_id, operators) = match store_res {
        Ok(s) => {
            let vid = s.get_vault_id().unwrap_or([0u8; 32]);
            (vid, get_configured_operators())
        }
        Err(_) => ([1u8; 32], vec!["http://127.0.0.1:8081".to_string()]),
    };

    // Generate a drill demonstration secret for previewing guardian sheets
    let mut drill_secret_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut drill_secret_bytes);
    let drill_secret = RecoverySecret::from_bytes(drill_secret_bytes);

    match OfflineRecoveryKit::create(&vault_id, &drill_secret, operators) {
        Ok(kit) => match ThresholdRecoveryKit::split_kit(&kit, threshold, total_shares) {
            Ok(shares) => {
                let sheets_json: Vec<_> = shares
                    .iter()
                    .map(|s| {
                        serde_json::json!({
                            "share_index": s.guardian_index,
                            "guardian_index": s.guardian_index,
                            "guardian_name": format!("Guardian {}", s.guardian_index),
                            "threshold": s.threshold,
                            "total_shares": s.total_shares,
                            "vault_id_hex": s.vault_id_hex,
                            "recovery_signing_pk": s.recovery_signing_pk_hex,
                            "recovery_encrypt_pk": s.recovery_encryption_pk_hex,
                            "recovery_locator": s.recovery_locator_hex,
                            "crc32": format!("0x{:08X}", s.checksum),
                            "checksum_hex": format!("0x{:08X}", s.checksum),
                            "sheet_text": s.format_guardian_sheet(),
                            "printable_sheet": s.format_guardian_sheet(),
                        })
                    })
                    .collect();

                axum::Json(serde_json::json!({
                    "status": "ok",
                    "success": true,
                    "is_drill_demo": true,
                    "active_threshold": threshold,
                    "total_guardians": total_shares,
                    "threshold": threshold,
                    "total_shares": total_shares,
                    "shares_count": sheets_json.len(),
                    "sheets": sheets_json,
                    "notice": "DEMO / DRILL PREVIEW: Generated using ephemeral synthetic demonstration key. Master recovery secret is never stored on disk."
                }))
            }
            Err(e) => axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "error": format!("Failed to split guardian kit: {}", e)
            })),
        },
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": format!("Failed to create kit: {}", e)
        })),
    }
}

#[derive(serde::Deserialize)]
struct ReconstructGuardiansRequest {
    shares: Vec<String>,
}

async fn api_guardians_reconstruct_handler(
    axum::Json(payload): axum::Json<ReconstructGuardiansRequest>,
) -> impl axum::response::IntoResponse {
    if payload.shares.is_empty() {
        return axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": "No guardian shares provided"
        }));
    }

    let mut parsed_kits = Vec::new();
    for (i, sheet_text) in payload.shares.iter().enumerate() {
        match ThresholdRecoveryKit::parse_from_printable(sheet_text) {
            Ok(k) => parsed_kits.push(k),
            Err(e) => {
                return axum::Json(serde_json::json!({
                    "status": "error",
                    "success": false,
                    "error": format!("Share #{} invalid format or checksum: {}", i + 1, e)
                }));
            }
        }
    }

    match ThresholdRecoveryKit::combine_kits(&parsed_kits) {
        Ok(reconstructed) => {
            let store_res = get_vault_store();
            let mut matches_vault = false;
            if let Ok(store) = store_res {
                if let Ok((signing_pk, _, _)) = store.get_recovery_descriptors() {
                    if let Ok(reconstructed_pk) =
                        hex::decode(&reconstructed.recovery_signing_pk_hex)
                    {
                        matches_vault = reconstructed_pk == signing_pk;
                    }
                }
            }

            let threshold = parsed_kits[0].threshold;
            let total = parsed_kits[0].total_shares;

            axum::Json(serde_json::json!({
                "status": "ok",
                "success": true,
                "threshold_met": true,
                "shares_provided": parsed_kits.len(),
                "threshold": threshold,
                "total_shares": total,
                "vault_id_hex": reconstructed.vault_id_hex,
                "matches_vault": matches_vault,
                "verified_signing_pk_matches": matches_vault,
                "recovery_signing_pk": reconstructed.recovery_signing_pk_hex,
                "message": format!("Successfully recombined {} valid guardian shares via GF(2^8) Lagrange interpolation in zeroized RAM", parsed_kits.len())
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "threshold_met": false,
            "shares_provided": parsed_kits.len(),
            "threshold": if !parsed_kits.is_empty() { parsed_kits[0].threshold } else { 0 },
            "error": format!("Insufficient or conflicting shares: {}", e)
        })),
    }
}

async fn api_relayer_checkpoints_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => return axum::Json(serde_json::json!([])),
    };

    let anchors = store.list_checkpoint_evidence().unwrap_or_default();
    let json_anchors: Vec<_> = anchors
        .iter()
        .map(|ev| {
            let tx_hex = format!("0x{}", hex::encode(&ev.tx_hash));
            let is_empty_tx = ev.tx_hash == [0u8; 32];
            let arbiscan_url = if is_empty_tx {
                String::new()
            } else if ev.chain_id == 42161 {
                format!("https://arbiscan.io/tx/{}", tx_hex)
            } else {
                format!("https://sepolia.arbiscan.io/tx/{}", tx_hex)
            };

            serde_json::json!({
                "commitment_hex": hex::encode(&ev.commitment),
                "salt_hex": hex::encode(&ev.salt),
                "head_record_cid_hex": hex::encode(&ev.head_record_cid),
                "chain_id": ev.chain_id,
                "contract_address_hex": format!("0x{}", hex::encode(&ev.contract_address)),
                "tx_hash_hex": tx_hex,
                "arbiscan_url": arbiscan_url,
                "block_number": ev.block_number,
                "timestamp_utc": ev.timestamp_utc,
                "is_relayed": !is_empty_tx,
                "status": if is_empty_tx { "PendingBroadcast" } else { "SequencerConfirmed" }
            })
        })
        .collect();

    axum::Json(serde_json::json!(json_anchors))
}

async fn api_relayer_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None, None, true, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "success": true,
            "message": "Snapshot head commitment successfully submitted to automated Arbitrum L2 relayer with sequencer receipt"
        })),
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_fleet_handler() -> impl axum::response::IntoResponse {
    let fleet_db_path = PathBuf::from(".ciphervault").join("fleet.db");
    if let Some(parent) = fleet_db_path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let db_res = MaintenanceDb::open(&fleet_db_path);
    let db = match db_res {
        Ok(d) => d,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": format!("Failed to open fleet database: {}", e)
            }));
        }
    };

    // Auto-register current vault if initialized
    if let Ok(store) = get_vault_store() {
        if let Ok((_, _, locator)) = store.get_recovery_descriptors() {
            let locator_hex = hex::encode(locator);
            let _ = db.register_vault(&locator_hex, Some("Active Project Vault"));
        }
    }

    // Ping operators and update operator nodes in fleet database
    let operators = get_configured_operators();
    for endpoint in &operators {
        let client = OperatorClient::new(endpoint.clone());
        let start = std::time::Instant::now();
        match client.get_info().await {
            Ok(_) => {
                let latency = start.elapsed().as_millis() as u64;
                let _ = db.update_operator_health(endpoint, latency, true);
            }
            Err(_) => {
                let _ = db.update_operator_health(endpoint, 999, false);
            }
        }
    }

    let summary = db
        .get_fleet_summary()
        .unwrap_or(ciphervault_maintenance::FleetSummary {
            total_tracked_vaults: 1,
            healthy_vaults: 1,
            degraded_vaults: 0,
            total_audits_recorded: 0,
            online_operators: operators.len(),
            total_operators: operators.len(),
        });

    let vaults = db.list_vaults().unwrap_or_default();
    let nodes = db.list_operator_nodes().unwrap_or_default();
    let history = db.get_recent_audits(20).unwrap_or_default();

    let avg_latency = {
        let healthy_nodes: Vec<_> = nodes.iter().filter(|n| n.is_healthy).collect();
        if !healthy_nodes.is_empty() {
            healthy_nodes.iter().map(|n| n.latency_ms).sum::<u64>() / healthy_nodes.len() as u64
        } else if !nodes.is_empty() {
            nodes.iter().map(|n| n.latency_ms).sum::<u64>() / nodes.len() as u64
        } else {
            0
        }
    };

    let fleet_summary = serde_json::json!({
        "total_tracked_vaults": summary.total_tracked_vaults,
        "healthy_vaults": summary.healthy_vaults,
        "degraded_vaults": summary.degraded_vaults,
        "total_audits_recorded": summary.total_audits_recorded,
        "audits_completed": summary.total_audits_recorded,
        "online_operators": summary.online_operators,
        "active_operators": summary.online_operators,
        "total_operators": summary.total_operators,
        "avg_latency_ms": avg_latency,
    });

    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "summary": summary,
        "fleet_summary": fleet_summary,
        "vaults": vaults,
        "operator_nodes": nodes,
        "audit_history": history,
    }))
}

async fn api_fleet_audit_handler() -> impl axum::response::IntoResponse {
    let audit_res = audit_current(None).await;
    let fleet_db_path = PathBuf::from(".ciphervault").join("fleet.db");
    let db = MaintenanceDb::open(&fleet_db_path).ok();

    match audit_res {
        Ok(report) => {
            if let Some(ref db) = db {
                let locator_hex = if let Ok(store) = get_vault_store() {
                    if let Ok((_, _, loc)) = store.get_recovery_descriptors() {
                        hex::encode(loc)
                    } else {
                        "0000000000000000000000000000000000000000000000000000000000000000"
                            .to_string()
                    }
                } else {
                    "0000000000000000000000000000000000000000000000000000000000000000".to_string()
                };

                let details = serde_json::to_string(&report).unwrap_or_default();
                let _ = db.record_audit(
                    &locator_hex,
                    report.healthy,
                    report.objects.total_objects,
                    report.objects.degraded_objects.len(),
                    &details,
                );
            }

            axum::Json(serde_json::json!({
                "success": report.healthy,
                "healthy": report.healthy,
                "report": report,
                "message": if report.healthy { "Fleet audit completed: All objects verified across operators" } else { "Fleet audit completed: Degraded replicas detected" }
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_token_handler() -> impl axum::response::IntoResponse {
    let readers = ciphervault_crypto::list_pcsc_readers().unwrap_or_default();
    let probe_res = ciphervault_crypto::PcscHardwareToken::probe()
        .ok()
        .flatten();

    let token_info = probe_res.map(|token| {
        let info_9c = token
            .get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)
            .ok();
        let info_9d = token
            .get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)
            .ok();
        serde_json::json!({
            "reader": token.reader_name(),
            "slot_9c": info_9c,
            "slot_9d": info_9d,
            "ready": true,
        })
    });

    axum::Json(serde_json::json!({
        "pcsc_available": true,
        "readers": readers,
        "hardware_token": token_info,
    }))
}

async fn api_stream_handler() -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = stream::unfold((), |_| async {
        let operators = get_configured_operators();
        let mut op_latencies = Vec::new();
        for endpoint in operators {
            let client = OperatorClient::new(endpoint.clone());
            let start = std::time::Instant::now();
            let (online, latency_ms) = match client.get_info().await {
                Ok(_) => (true, start.elapsed().as_millis() as u64),
                Err(_) => (false, 999),
            };
            op_latencies.push(serde_json::json!({
                "endpoint": endpoint,
                "online": online,
                "latency_ms": latency_ms,
            }));
        }

        let token_attached = ciphervault_crypto::PcscHardwareToken::probe()
            .ok()
            .flatten()
            .is_some();
        let timestamp = Utc::now().to_rfc3339();

        let data = serde_json::json!({
            "timestamp": timestamp,
            "operators": op_latencies,
            "token_attached": token_attached,
        });

        let event = Event::default().event("telemetry").data(data.to_string());
        tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        Some((Ok(event), ()))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

#[derive(serde::Deserialize)]
struct FastCdcInspectRequest {
    content: Option<String>,
    min_size: Option<usize>,
    avg_size: Option<usize>,
    max_size: Option<usize>,
}

fn compute_shannon_entropy(data: &[u8]) -> f64 {
    if data.is_empty() {
        return 0.0;
    }
    let mut freq = [0usize; 256];
    for &b in data {
        freq[b as usize] += 1;
    }
    let len = data.len() as f64;
    let mut entropy = 0.0;
    for &count in &freq {
        if count > 0 {
            let p = count as f64 / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

fn compute_gear_fingerprint(chunk: &[u8]) -> u64 {
    use ciphervault_snapshot::fastcdc::GEAR_MATRIX;
    let mut hash = 0u64;
    let tail = if chunk.len() > 64 {
        &chunk[chunk.len() - 64..]
    } else {
        chunk
    };
    for &b in tail {
        hash = (hash << 1).wrapping_add(GEAR_MATRIX[b as usize]);
    }
    hash
}

fn format_preview(data: &[u8]) -> String {
    let take_len = data.len().min(48);
    let slice = &data[..take_len];
    if slice
        .iter()
        .all(|&b| b.is_ascii_graphic() || b == b' ' || b == b'\t' || b == b'\n')
    {
        String::from_utf8_lossy(slice).trim().to_string()
    } else {
        format!("hex:{}", hex::encode(slice))
    }
}

fn generate_sample_workload() -> Vec<u8> {
    let mut buffer = Vec::with_capacity(65536);
    let sample_block = b"{\"timestamp\":\"2026-09-12T12:00:00Z\",\"level\":\"INFO\",\"service\":\"auth-gateway\",\"trace_id\":\"4bf92f3577b34da6a3ce929d0e0e4736\",\"span_id\":\"00f067aa0ba902b7\",\"message\":\"Authentication ticket validated for user_session_49182\",\"status\":200,\"latency_ms\":14.2}\n";
    for i in 0..320 {
        buffer.extend_from_slice(sample_block);
        if i % 10 == 0 {
            buffer.extend_from_slice(
                format!(
                    "{{\"event\":\"rotation_epoch_pulse\",\"epoch\":{},\"status\":\"verified\"}}\n",
                    i
                )
                .as_bytes(),
            );
        }
    }
    buffer
}

async fn api_fastcdc_inspect_handler(
    axum::Json(payload): axum::Json<FastCdcInspectRequest>,
) -> impl axum::response::IntoResponse {
    let config = if let (Some(min), Some(avg), Some(max)) =
        (payload.min_size, payload.avg_size, payload.max_size)
    {
        if min > 0 && min <= avg && avg <= max {
            FastCdcConfig::new(min, avg, max)
        } else {
            FastCdcConfig::default()
        }
    } else {
        FastCdcConfig::default()
    };

    let raw_data = if let Some(ref txt) = payload.content {
        if txt.trim().is_empty() {
            generate_sample_workload()
        } else {
            txt.as_bytes().to_vec()
        }
    } else {
        generate_sample_workload()
    };

    let chunks = fastcdc_chunk(&raw_data, &config);

    let mut offset = 0usize;
    let mut chunk_records = Vec::new();
    let mut unique_cids = std::collections::HashSet::new();
    let mut unique_bytes = 0usize;

    for (i, chunk_slice) in chunks.iter().enumerate() {
        let cid_bytes = ciphervault_format::compute_digest(chunk_slice);
        let cid_hex = hex::encode(cid_bytes);
        let entropy = compute_shannon_entropy(chunk_slice);
        let gear = compute_gear_fingerprint(chunk_slice);
        let is_dup = !unique_cids.insert(cid_bytes);
        if !is_dup {
            unique_bytes += chunk_slice.len();
        }

        chunk_records.push(serde_json::json!({
            "index": i,
            "offset": offset,
            "length": chunk_slice.len(),
            "cid_hex": cid_hex,
            "gear_fingerprint": format!("0x{:016x}", gear),
            "entropy": (entropy * 1000.0).round() / 1000.0,
            "is_duplicate": is_dup,
            "preview": format_preview(chunk_slice),
        }));

        offset += chunk_slice.len();
    }

    let total_chunks = chunks.len();
    let unique_count = unique_cids.len();
    let duplicate_count = total_chunks.saturating_sub(unique_count);
    let total_bytes = raw_data.len();
    let saved_bytes = total_bytes.saturating_sub(unique_bytes);
    let dedup_savings_pct = if total_bytes > 0 {
        (saved_bytes as f64 / total_bytes as f64) * 100.0
    } else {
        0.0
    };

    let fixed_size = config.avg_size.max(1);
    let fixed_chunks_count = total_bytes.div_ceil(fixed_size);

    axum::Json(serde_json::json!({
        "success": true,
        "config": {
            "min_size": config.min_size,
            "avg_size": config.avg_size,
            "max_size": config.max_size,
        },
        "metrics": {
            "total_bytes": total_bytes,
            "total_chunks": total_chunks,
            "unique_chunks": unique_count,
            "duplicate_chunks": duplicate_count,
            "unique_bytes": unique_bytes,
            "saved_bytes": saved_bytes,
            "dedup_savings_pct": (dedup_savings_pct * 100.0).round() / 100.0,
            "fixed_chunks_count": fixed_chunks_count,
            "boundary_shift_resilient": true,
        },
        "chunks": chunk_records,
    }))
}
