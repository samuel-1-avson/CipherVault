use anyhow::{bail, Context, Result};
use chrono::{TimeZone, Utc};
use clap::{CommandFactory, Parser, Subcommand};
use colored::*;
use ed25519_dalek::SigningKey;
use rand::RngCore;
use reqwest::Client as HttpClient;
use std::fs::{self, OpenOptions};
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::sync::{OnceLock, RwLock};
use std::time::{Duration, Instant};
use zeroize::Zeroize;

use axum::body::Bytes;
use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{
    future::join_all,
    stream::{self, Stream},
};

use ciphervault_crypto::{
    generate_signing_key, HardwareSecurityModule, RecoverySecret, VaultEpochKey,
};
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, ChunkWireObject, DeviceCertificate, GenesisRecord,
    HeadRecord, SnapshotManifest, SnapshotRecord, PROTOCOL_VERSION,
};
use ciphervault_local_store::{AccountStore, LocalVaultStore};
use ciphervault_maintenance::MaintenanceDb;
use ciphervault_recovery::OfflineRecoveryKit;
use ciphervault_snapshot::{
    create_snapshot, create_snapshot_with_signer, decrypt_snapshot, fastcdc_chunk,
    restore_snapshot, DeviceSigner, FastCdcConfig,
};
use ciphervault_storage::{MultiOperatorPool, OperatorClient};

pub mod diff;
pub mod dotenv;
pub mod tui;

const VAULT_DIR: &str = ".ciphervault";
const DB_FILE: &str = "vault.db";
const RECOVERY_FILE: &str = "recovery_kit_backup.txt";
const OPERATORS_FILE: &str = "operators.json";

#[derive(Parser)]
#[command(name = "ciphervault")]
#[command(author = "CipherVault Team")]
#[command(version)]
#[command(about = "Decentralized, encrypted version control for confidential files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Manage the optional CipherVault control-plane account on this device
    Auth {
        #[command(subcommand)]
        sub: AuthSubcommand,
    },

    /// Manage devices enrolled in the local CipherVault account
    Device {
        #[command(subcommand)]
        sub: DeviceSubcommand,
    },

    /// Link the current local vault to the optional CipherVault account
    Vault {
        #[command(subcommand)]
        sub: VaultSubcommand,
    },

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

        #[arg(
            short = 'i',
            long,
            help = "Automatically import and track secret files discovered in .gitignore"
        )]
        import_gitignore: bool,

        #[arg(long, help = "Specify PC/SC smartcard reader name or substring filter")]
        reader: Option<String>,

        #[arg(long, help = "Hardware token user PIN for automated verification")]
        pin: Option<String>,
    },

    /// Add confidential files to vault tracking (e.g. .env, keys)
    Track {
        #[arg(help = "Files to track")]
        paths: Vec<PathBuf>,

        #[arg(
            short = 'i',
            long,
            help = "Scan .gitignore for confidential secret files (.env, keys, certs) and track them"
        )]
        from_gitignore: bool,

        #[arg(
            long,
            help = "Do not automatically append newly tracked files to .gitignore"
        )]
        no_gitignore: bool,
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

        #[arg(
            long,
            help = "Create and commit snapshot locally without replicating to remote operators"
        )]
        local: bool,

        #[arg(
            long,
            help = "Automatically anchor newly created snapshot head commitment to Arbitrum L2"
        )]
        anchor: bool,

        #[arg(long, help = "Specify PC/SC smartcard reader name or substring filter")]
        reader: Option<String>,

        #[arg(long, help = "Hardware token user PIN for automated verification")]
        pin: Option<String>,
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

        #[arg(
            long,
            help = "Validate snapshot signature or authenticate against physical hardware token"
        )]
        hardware_token: bool,

        #[arg(long, help = "Specify PC/SC smartcard reader name or substring filter")]
        reader: Option<String>,

        #[arg(long, help = "Hardware token user PIN for automated verification")]
        pin: Option<String>,
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

        #[arg(
            long,
            help = "Require out-of-band cryptographic approval receipt from team lead or guardian before restoring"
        )]
        require_approval: bool,
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

        #[arg(
            long,
            help = "Run in continuous daemon mode, periodically settling state roots on Arbitrum"
        )]
        daemon: bool,

        #[arg(
            long,
            default_value = "3600",
            help = "Interval in seconds between periodic anchor checks in daemon mode (default: 3600)"
        )]
        interval: u64,
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

    /// Publish a signed public checkpoint feed from local vault evidence
    PublishPublicFeed {
        #[arg(short, long, help = "Output JSON path consumed by the public explorer")]
        output: PathBuf,

        #[arg(
            long,
            default_value = "Arbitrum One",
            help = "Human-readable network label included in each checkpoint"
        )]
        network: String,
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

    /// Open the production cloud dashboard or launch an offline local inspector
    Ui {
        #[arg(
            long,
            default_value = "127.0.0.1",
            help = "Host address to bind when serving (a loopback address is required with --local)"
        )]
        host: String,

        #[arg(
            short,
            long,
            default_value = "8080",
            help = "Port to serve web dashboard on in local mode"
        )]
        port: u16,

        #[arg(long, help = "Do not automatically open default web browser")]
        no_browser: bool,

        #[arg(
            long,
            conflicts_with = "serve",
            help = "Run an isolated local offline server instead of opening the production cloud dashboard"
        )]
        local: bool,

        #[arg(
            long,
            conflicts_with = "local",
            help = "Start the public read-only explorer HTTP server (private vault APIs remain disabled)"
        )]
        serve: bool,

        #[arg(
            long,
            default_value = "https://vault.cipherv.online",
            help = "Production cloud dashboard URL"
        )]
        url: String,
    },

    /// Launch interactive terminal user interface (TUI)
    Tui {
        #[arg(
            long,
            default_value = "3000",
            help = "Operator telemetry polling interval in milliseconds"
        )]
        poll_ms: u64,
    },

    /// Watch tracked confidential files and automatically create snapshots on save
    Watch {
        #[arg(
            short,
            long,
            default_value = "2",
            help = "Debounce window in seconds before capturing snapshot"
        )]
        debounce: u64,

        #[arg(
            short,
            long,
            help = "Enable automatic remote replication to operators on snapshot"
        )]
        sync: bool,
    },

    /// Run a command with decrypted secrets injected into its environment (zero-disk exposure)
    Run {
        #[arg(
            short,
            long,
            help = "Snapshot ID (hex) to source secrets from (defaults to latest head)"
        )]
        snapshot: Option<String>,

        #[arg(
            short,
            long,
            help = "Specific secret file to load (e.g. .env.production)"
        )]
        env_file: Option<String>,

        #[arg(
            long,
            help = "Do not inherit host process environment variables (except essential OS paths)"
        )]
        no_inherit: bool,

        #[arg(
            long,
            help = "Display decrypted variable keys without executing command or exposing values"
        )]
        dry_run: bool,

        #[arg(short, long, help = "Suppress CipherVault informational output banner")]
        quiet: bool,

        #[arg(
            long,
            num_args = 1..,
            help = "Additional KEY=VALUE overrides to inject"
        )]
        set: Option<Vec<String>>,

        #[arg(
            trailing_var_arg = true,
            required = true,
            help = "Command and arguments to execute"
        )]
        command: Vec<String>,
    },

    /// Compare changes in confidential files across snapshots or against working tree
    Diff {
        #[arg(
            help = "Old snapshot ID to compare (or compare working directory against latest head)"
        )]
        snapshot_a: Option<String>,

        #[arg(help = "New snapshot ID to compare against snapshot_a")]
        snapshot_b: Option<String>,

        #[arg(short, long, help = "Limit diff to a specific relative file path")]
        file: Option<String>,

        #[arg(long, help = "Reveal full unmasked secret values in diff output")]
        reveal: bool,

        #[arg(long, help = "Output diff report in structured JSON format")]
        json: bool,
    },

    /// Pull the latest snapshot from independent operators and update local files
    Pull {
        #[arg(
            short,
            long,
            help = "Check for remote updates without modifying local working files"
        )]
        dry_run: bool,

        #[arg(
            short,
            long,
            help = "Overwrite modified local files with remote snapshot contents"
        )]
        force: bool,
    },

    /// Generate shell autocompletion script for your shell
    Completions {
        #[arg(
            value_enum,
            help = "Target shell (bash, elvish, fish, powershell, zsh)"
        )]
        shell: clap_complete::Shell,
    },

    /// Manage physical hardware security tokens (YubiKey PIV / PC/SC)
    Token {
        #[command(subcommand)]
        sub: TokenSubcommand,
    },

    /// Inspect discovered peer operators and dynamic P2P gossip cluster
    Peers {
        #[arg(
            short,
            long,
            help = "Query operators to dynamically discover new peer nodes"
        )]
        discover: bool,
    },

    /// Out-of-band cryptographic approval and multi-party authorization
    Approve {
        #[command(subcommand)]
        sub: ApproveSubcommand,
    },
}

#[derive(Subcommand)]
enum AuthSubcommand {
    /// Create a local account identity; no vault keys leave this device
    Init {
        #[arg(long, help = "Human-readable account display name")]
        name: Option<String>,
    },

    /// Unlock the local account key and create a short-lived device-bound session
    Login,

    /// Revoke the local account session
    Logout,

    /// Show account, device, vault-link, and session state
    Status,
}

#[derive(Subcommand)]
enum DeviceSubcommand {
    /// List devices registered to the local account
    List,

    /// Revoke a device by its 32-byte hex device ID
    Revoke { device_id: String },
}

#[derive(Subcommand)]
enum VaultSubcommand {
    /// Link the current local vault and its device identity to the account
    Link {
        #[arg(
            long,
            default_value = "Local vault",
            help = "Display alias for the vault"
        )]
        alias: String,
    },

    /// Remove the current local vault from the account registry
    Unlink,
}

#[derive(Subcommand)]
enum ApproveSubcommand {
    /// List pending out-of-band authorization challenges across the cluster
    List,

    /// Cryptographically sign and approve a pending authorization challenge
    Sign {
        #[arg(help = "The 32-character hex ID of the challenge to approve")]
        challenge_id: String,

        #[arg(short, long, help = "Name or role of the approving guardian/lead")]
        name: Option<String>,
    },

    /// Inspect approval status and collected signatures for a challenge
    Status {
        #[arg(help = "The 32-character hex ID of the challenge")]
        challenge_id: String,
    },
}

#[derive(Subcommand)]
enum TokenSubcommand {
    /// Display connection status of attached PC/SC smartcard readers and tokens
    Status {
        #[arg(short, long, help = "Optional reader name filter")]
        reader: Option<String>,
    },

    /// Probe physical token and inspect PIV Slot 9C (Signing) and Slot 9D (Key Management)
    Probe {
        #[arg(short, long, help = "Optional reader name filter")]
        reader: Option<String>,
    },

    /// Enumerate all detected PC/SC smartcard readers and card presence status
    List,

    /// Inspect detailed cryptographic configuration across all PIV slots (9A, 9C, 9D, 9E)
    Slots {
        #[arg(short, long, help = "Optional reader name filter")]
        reader: Option<String>,
    },

    /// Test or securely cache a hardware token PIN in memory / session
    Pin {
        #[arg(short, long, help = "PIN value to verify and cache")]
        pin: Option<String>,

        #[arg(long, help = "Test PIN against attached hardware token")]
        test: bool,

        #[arg(long, help = "Clear cached PIN from memory session")]
        clear: bool,
    },

    /// Select and persist default active hardware token reader for this vault
    Select {
        #[arg(short, long, help = "Reader name or substring to select")]
        reader: Option<String>,
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
        Commands::Auth { sub } => match sub {
            AuthSubcommand::Init { name } => cmd_auth_init(name),
            AuthSubcommand::Login => cmd_auth_login(),
            AuthSubcommand::Logout => cmd_auth_logout(),
            AuthSubcommand::Status => cmd_auth_status(),
        },
        Commands::Device { sub } => match sub {
            DeviceSubcommand::List => cmd_device_list(),
            DeviceSubcommand::Revoke { device_id } => cmd_device_revoke(&device_id).await,
        },
        Commands::Vault { sub } => match sub {
            VaultSubcommand::Link { alias } => cmd_vault_link(&alias),
            VaultSubcommand::Unlink => cmd_vault_unlink(),
        },
        Commands::Init {
            force,
            operators,
            save_kit,
            hardware_token,
            import_gitignore,
            reader,
            pin,
        } => cmd_init(
            force,
            operators,
            save_kit,
            hardware_token,
            import_gitignore,
            reader,
            pin,
        ),
        Commands::Track {
            paths,
            from_gitignore,
            no_gitignore,
        } => cmd_track(paths, from_gitignore, no_gitignore),
        Commands::Untrack { paths } => cmd_untrack(paths),
        Commands::Status => cmd_status(),
        Commands::Push {
            message,
            touch,
            pos: _,
            local,
            anchor,
            reader,
            pin,
        } => cmd_push(message, touch, local, anchor, reader, pin).await,
        Commands::History => cmd_history(),
        Commands::Restore {
            snapshot,
            to,
            hardware_token,
            reader,
            pin,
        } => cmd_restore(snapshot, to, hardware_token, reader, pin),
        Commands::Recover {
            kit,
            shares,
            to,
            require_approval,
        } => cmd_recover(kit, shares, to, require_approval).await,
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
            daemon,
            interval,
        } => {
            if daemon {
                println!(
                    "{}",
                    "=======================================================".cyan()
                );
                println!(
                    "{}",
                    "  CipherVault Arbitrum L2 Periodic Anchoring Daemon"
                        .bold()
                        .green()
                );
                println!("  Check Interval:  {}s", interval);
                println!("  Target Chain:    Arbitrum (Auto-Relay: {})", auto_relay);
                println!(
                    "{}",
                    "=======================================================".cyan()
                );

                // Run initial anchor check immediately
                println!(
                    "[{}] Executing initial Arbitrum anchor check...",
                    chrono::Utc::now().to_rfc3339()
                );
                if let Err(e) = cmd_anchor(
                    head.clone(),
                    rpc.clone(),
                    contract.clone(),
                    chain_id,
                    tx_hash.clone(),
                    raw_tx.clone(),
                    auto_relay,
                    relayer_url.clone(),
                )
                .await
                {
                    eprintln!("Notice: Initial anchor check: {}", e);
                }

                loop {
                    tokio::select! {
                        _ = tokio::signal::ctrl_c() => {
                            println!("\nShutdown signal received. Exiting anchoring daemon gracefully.");
                            break;
                        }
                        _ = tokio::time::sleep(std::time::Duration::from_secs(interval)) => {
                            println!(
                                "[{}] Executing periodic Arbitrum anchor check...",
                                chrono::Utc::now().to_rfc3339()
                            );
                            if let Err(e) = cmd_anchor(
                                head.clone(),
                                rpc.clone(),
                                contract.clone(),
                                chain_id,
                                tx_hash.clone(),
                                raw_tx.clone(),
                                auto_relay,
                                relayer_url.clone(),
                            )
                            .await
                            {
                                eprintln!("Notice: Periodic anchor check: {}", e);
                            }
                        }
                    }
                }
                Ok(())
            } else {
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
        }
        Commands::VerifyAnchor { head, rpc } => cmd_verify_anchor(head, rpc).await,
        Commands::PublishPublicFeed { output, network } => cmd_publish_public_feed(output, network),
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
            local,
            serve,
            url,
        } => cmd_ui(host, port, no_browser, local, serve, url).await,
        Commands::Tui { poll_ms } => tui::run_tui(poll_ms).await,
        Commands::Watch { debounce, sync } => cmd_watch(debounce, sync).await,
        Commands::Run {
            snapshot,
            env_file,
            no_inherit,
            dry_run,
            quiet,
            set,
            command,
        } => cmd_run(snapshot, env_file, no_inherit, dry_run, quiet, set, command).await,
        Commands::Diff {
            snapshot_a,
            snapshot_b,
            file,
            reveal,
            json,
        } => cmd_diff(snapshot_a, snapshot_b, file, reveal, json),
        Commands::Pull { dry_run, force } => cmd_pull(dry_run, force).await,
        Commands::Completions { shell } => {
            cmd_completions(shell);
            Ok(())
        }
        Commands::Peers { discover } => cmd_peers(discover).await,
        Commands::Approve { sub } => match sub {
            ApproveSubcommand::List => cmd_approve_list().await,
            ApproveSubcommand::Sign { challenge_id, name } => {
                cmd_approve_sign(challenge_id, name).await
            }
            ApproveSubcommand::Status { challenge_id } => cmd_approve_status(challenge_id).await,
        },
    }
}

static ACTIVE_VAULT_PATH: std::sync::RwLock<Option<PathBuf>> = std::sync::RwLock::new(None);

pub fn set_active_vault_path(path: Option<PathBuf>) {
    if let Ok(mut guard) = ACTIVE_VAULT_PATH.write() {
        *guard = path;
    }
}

pub fn get_active_vault_path() -> PathBuf {
    if let Ok(guard) = ACTIVE_VAULT_PATH.read() {
        if let Some(ref p) = *guard {
            return p.clone();
        }
    }
    Path::new(VAULT_DIR).join(DB_FILE)
}

pub fn get_vault_store() -> Result<LocalVaultStore> {
    let path = get_active_vault_path();
    if !path.exists() {
        bail!(
            "No CipherVault found at '{}'. Run '{}' first.",
            path.display(),
            "ciphervault init".cyan()
        );
    }
    LocalVaultStore::open(&path).context("Failed to open local vault database")
}

#[derive(serde::Serialize, serde::Deserialize, Clone, Debug)]
pub struct WorkspaceVaultInfo {
    pub name: String,
    pub path: String,
    pub db_path: String,
    pub vault_id: String,
    pub active_head_cid: Option<String>,
    pub snapshot_count: usize,
    pub tracked_files_count: usize,
    pub is_active: bool,
    pub last_modified: String,
}

pub fn discover_workspace_vaults() -> Vec<WorkspaceVaultInfo> {
    let current_dir = std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let mut discovered = Vec::new();
    let mut searched_paths = std::collections::HashSet::new();

    let default_db = current_dir.join(VAULT_DIR).join(DB_FILE);
    if default_db.exists() {
        searched_paths.insert(default_db.clone());
    }

    for entry in walkdir::WalkDir::new(&current_dir)
        .max_depth(3)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_file() && entry.file_name() == DB_FILE {
            let p = entry.into_path();
            if let Some(parent) = p.parent() {
                if parent.file_name().and_then(|n| n.to_str()) == Some(VAULT_DIR) {
                    searched_paths.insert(p);
                }
            }
        }
    }

    let active_path = get_active_vault_path();

    for db_path in searched_paths {
        if let Ok(store) = LocalVaultStore::open(&db_path) {
            let vault_id = store.get_vault_id().unwrap_or_default();
            let vault_id_hex = hex::encode(vault_id);
            let head = store.get_active_head().ok().flatten();
            let head_cid = head.as_ref().map(|h| hex::encode(&h.snapshot_id));
            let snaps = store.list_snapshots().unwrap_or_default();
            let tracked = store.list_tracked_files().unwrap_or_default();

            let parent_folder = db_path
                .parent()
                .and_then(|p| p.parent())
                .unwrap_or(&current_dir);
            let raw_name = parent_folder
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("Vault")
                .to_string();

            let is_active = db_path == active_path
                || (active_path.is_relative() && current_dir.join(&active_path) == db_path);

            let last_modified = fs::metadata(&db_path)
                .and_then(|m| m.modified())
                .map(|t| chrono::DateTime::<Utc>::from(t).to_rfc3339())
                .unwrap_or_else(|_| Utc::now().to_rfc3339());

            discovered.push(WorkspaceVaultInfo {
                name: if is_active {
                    format!("{} (Active)", raw_name)
                } else {
                    raw_name
                },
                path: parent_folder.display().to_string(),
                db_path: db_path.display().to_string(),
                vault_id: vault_id_hex,
                active_head_cid: head_cid,
                snapshot_count: snaps.len(),
                tracked_files_count: tracked.len(),
                is_active,
                last_modified,
            });
        }
    }

    discovered.sort_by(|a, b| {
        b.is_active
            .cmp(&a.is_active)
            .then_with(|| a.name.cmp(&b.name))
    });
    discovered
}

fn get_saved_token_reader() -> Option<String> {
    let cfg_path = Path::new(VAULT_DIR).join("token_config.json");
    if cfg_path.exists() {
        if let Ok(text) = fs::read_to_string(&cfg_path) {
            if let Ok(val) = serde_json::from_str::<serde_json::Value>(&text) {
                return val
                    .get("reader")
                    .and_then(|r| r.as_str())
                    .map(|s| s.to_string());
            }
        }
    }
    None
}

fn save_token_reader_preference(reader: &str) -> Result<()> {
    let vault_dir = Path::new(VAULT_DIR);
    if vault_dir.exists() {
        let cfg_path = vault_dir.join("token_config.json");
        let payload = serde_json::json!({
            "reader": reader,
            "updated_at": Utc::now().to_rfc3339(),
        });
        fs::write(&cfg_path, serde_json::to_string_pretty(&payload)?)?;
    }
    Ok(())
}

fn current_device_identity() -> Result<(String, String, String)> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_key, _, _) = store.get_device_state()?;
    Ok((
        hex::encode(vault_id),
        hex::encode(device_id),
        hex::encode(device_key.verifying_key().as_bytes()),
    ))
}

/// Creates an operator pool and, when this vault is linked to the optional
/// account registry, propagates the same account/device identifiers into every
/// operator client. Accountless vaults retain the legacy protocol.
fn configured_operator_pool(endpoints: Vec<String>) -> MultiOperatorPool {
    let pool = MultiOperatorPool::new(endpoints);
    if let (Ok(account), Ok((vault_id, device_id, device_pk))) =
        (AccountStore::open(None), current_device_identity())
    {
        if account.is_vault_linked(&vault_id) && account.is_device_active(&device_id, &device_pk) {
            pool.set_account_identity(account.account_id(), &device_id);
        }
    }
    pool
}

fn cmd_auth_init(name: Option<String>) -> Result<()> {
    let account = AccountStore::create(name.as_deref(), None)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "CipherVault account created.".bold().green());
    println!("  Account ID:   {}", account.account_id().yellow());
    println!("  Display name: {}", account.record().display_name);
    println!("  Public key:   {}", account.public_key_hex().cyan());
    println!("  Metadata:     {}", AccountStore::default_path().display());
    println!(
        "\nThe account is a control-plane identity. Vault keys and the offline recovery secret remain local to each vault."
    );
    Ok(())
}

fn cmd_auth_login() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let device = current_device_identity().ok();
    // An account can be logged in before any vault is linked. Bind the
    // session to a device only when that device is already enrolled for the
    // current vault; `vault link` performs the enrollment step.
    let device_id = device
        .as_ref()
        .and_then(|(vault_id, device_id, device_pk)| {
            (account.is_vault_linked(vault_id) && account.is_device_active(device_id, device_pk))
                .then_some(device_id.as_str())
        });
    let status = account
        .login(device_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!(
        "{}",
        "CipherVault account session established.".bold().green()
    );
    println!("  Account ID: {}", status.account_id.yellow());
    if let Some(device_id) = status.device_id_hex {
        println!("  Device:     {}", device_id.cyan());
        println!("  Session:    device-bound (30 minutes)");
    } else {
        println!("  Session:    account-only (link a vault to bind this device)");
    }
    if let Ok(endpoint) = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT") {
        if !endpoint.trim().is_empty() {
            println!(
                "  Hosted endpoint: {} (remote exchange remains deployment work)",
                endpoint
            );
        }
    } else {
        println!("  Hosted endpoint: not configured; this is a local account session");
    }
    Ok(())
}

fn cmd_auth_logout() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    account
        .logout()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "CipherVault account session revoked.".green());
    Ok(())
}

fn cmd_auth_status() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let session = account.session_status();
    println!("{}", "CipherVault account".bold().cyan());
    println!("  Account ID:   {}", account.account_id().yellow());
    println!("  Display name: {}", account.record().display_name);
    println!("  Public key:   {}", account.public_key_hex());
    println!("  Metadata:     {}", AccountStore::default_path().display());
    println!("  Devices:      {}", account.record().devices.len());
    println!("  Vault links:  {}", account.record().vaults.len());
    println!(
        "  Session:      {}",
        if session.authenticated {
            "authenticated"
        } else {
            "signed out"
        }
    );
    if let Some(expires) = session.expires_at_utc {
        println!("  Session expiry: {}", expires);
    }
    Ok(())
}

fn cmd_device_list() -> Result<()> {
    let account = AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if account.record().devices.is_empty() {
        println!(
            "No devices are enrolled in account {}.",
            account.account_id()
        );
        return Ok(());
    }
    println!("Devices for {}:", account.account_id().yellow());
    for device in &account.record().devices {
        let state = if device.revoked_at_utc.is_some() {
            "REVOKED"
        } else {
            "ACTIVE"
        };
        println!(
            "  {}  {}  {}  {}",
            device.device_id_hex.cyan(),
            state,
            device.label,
            device.public_key_hex
        );
    }
    Ok(())
}

async fn sync_hosted_device_revocation(account: &AccountStore, device_id: &str) -> Result<()> {
    let endpoint = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .context("CIPHERVAULT_ACCOUNT_ENDPOINT is not configured")?;
    let endpoint = endpoint.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        bail!("CIPHERVAULT_ACCOUNT_ENDPOINT is empty");
    }

    // The hosted service only accepts a short-lived bearer session. Obtain it
    // with the account key without persisting or transmitting the private key.
    // If a current vault device is available, bind the session to that device;
    // otherwise use an account-only session for administrative revocation.
    let current_device = current_device_identity().ok().map(|(_, id, _)| id);
    let challenge_response = HttpClient::new()
        .post(format!("{endpoint}/v1/sessions/challenge"))
        .json(&serde_json::json!({
            "account_id": account.account_id(),
            "device_id_hex": current_device,
        }))
        .send()
        .await
        .context("requesting hosted account login challenge")?
        .error_for_status()
        .context("hosted account login challenge was rejected")?;
    let challenge: serde_json::Value = challenge_response
        .json()
        .await
        .context("decoding hosted account login challenge")?;
    let challenge_id = challenge
        .get("challenge_id")
        .and_then(serde_json::Value::as_str)
        .context("hosted login challenge did not include challenge_id")?;
    let nonce_hex = challenge
        .get("nonce_hex")
        .and_then(serde_json::Value::as_str)
        .context("hosted login challenge did not include nonce_hex")?;
    let signing_bytes = serde_json::to_vec(&(
        account.account_id(),
        current_device.as_deref(),
        Option::<&str>::None,
        challenge_id,
        nonce_hex,
    ))?;
    let signature = account
        .sign_challenge(b"account_login", &signing_bytes)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let session_response = HttpClient::new()
        .post(format!("{endpoint}/v1/sessions"))
        .json(&serde_json::json!({
            "challenge_id": challenge_id,
            "signature_hex": hex::encode(signature),
        }))
        .send()
        .await
        .context("requesting hosted account session")?
        .error_for_status()
        .context("hosted account session was rejected")?;
    let session: serde_json::Value = session_response
        .json()
        .await
        .context("decoding hosted account session")?;
    let token = session
        .get("token")
        .and_then(serde_json::Value::as_str)
        .context("hosted account session did not include a token")?;
    HttpClient::new()
        .post(format!(
            "{endpoint}/v1/accounts/{}/devices/{}/revoke",
            account.account_id(),
            device_id
        ))
        .bearer_auth(token)
        .send()
        .await
        .context("requesting hosted device revocation")?
        .error_for_status()
        .context("hosted device revocation was rejected")?;
    Ok(())
}

async fn cmd_device_revoke(device_id: &str) -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let changed = account
        .revoke_device(device_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if !changed {
        bail!(
            "Device '{}' is not enrolled or is already revoked.",
            device_id
        );
    }
    println!(
        "{}",
        "Device revoked and local account session invalidated.".green()
    );
    if std::env::var_os("CIPHERVAULT_ACCOUNT_ENDPOINT").is_some() {
        match sync_hosted_device_revocation(&account, device_id).await {
            Ok(()) => println!("Hosted account session and operator bindings revoked."),
            Err(error) => eprintln!(
                "{} Hosted revocation could not be confirmed: {error}",
                "Warning:".yellow()
            ),
        }
    }
    Ok(())
}

fn cmd_vault_link(alias: &str) -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (vault_id, device_id, device_pk) = current_device_identity()?;
    account
        .register_device(&device_id, &device_pk, alias)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    account
        .link_vault(&vault_id, alias, "owner")
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    // Linking a vault establishes the device binding for the local account
    // session. This does not transmit vault keys or plaintext.
    account
        .login(Some(&device_id))
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "Vault linked to CipherVault account.".bold().green());
    println!("  Vault ID: {}", vault_id.yellow());
    println!("  Device:   {}", device_id.cyan());
    println!("  Role:     owner");
    Ok(())
}

fn cmd_vault_unlink() -> Result<()> {
    let mut account =
        AccountStore::open(None).map_err(|error| anyhow::anyhow!(error.to_string()))?;
    let (vault_id, _, _) = current_device_identity()?;
    let changed = account
        .unlink_vault(&vault_id)
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    if !changed {
        bail!("Vault '{}' is not linked to this account.", vault_id);
    }
    account
        .logout()
        .map_err(|error| anyhow::anyhow!(error.to_string()))?;
    println!("{}", "Vault unlinked from CipherVault account.".green());
    Ok(())
}

pub fn resolve_hardware_token(
    reader_arg: Option<&str>,
    pin_arg: Option<&str>,
    headless: bool,
) -> Result<ciphervault_crypto::PcscHardwareToken> {
    let saved_reader = get_saved_token_reader();
    let reader_filter = reader_arg.or(saved_reader.as_deref());

    let tokens = ciphervault_crypto::probe_all()?;
    if tokens.is_empty() {
        bail!(
            "Hardware token required (--hardware-token, --touch, or hardware-bound vault), but no physical YubiKey or PIV smartcard token was detected in PC/SC readers."
        );
    }

    let selected_token = if let Some(filter) = reader_filter {
        let f_lower = filter.to_lowercase();
        tokens
            .into_iter()
            .find(|t| t.reader_name().to_lowercase().contains(&f_lower))
            .ok_or_else(|| {
                anyhow::anyhow!(
                    "No attached hardware token matched reader filter '{}'",
                    filter
                )
            })?
    } else if tokens.len() == 1 {
        tokens.into_iter().next().unwrap()
    } else {
        if !headless && std::io::stdin().is_terminal() {
            println!(
                "\n{}",
                "Multiple PIV hardware security tokens detected:"
                    .bold()
                    .cyan()
            );
            for (idx, t) in tokens.iter().enumerate() {
                println!("  [{}] {}", idx + 1, t.reader_name().green().bold());
            }
            print!("Select hardware token [1-{}]: ", tokens.len());
            let _ = std::io::stdout().flush();
            let mut input = String::new();
            std::io::stdin().read_line(&mut input)?;
            let choice: usize = input.trim().parse().unwrap_or(1);
            let idx = if choice >= 1 && choice <= tokens.len() {
                choice - 1
            } else {
                0
            };
            tokens[idx].clone()
        } else {
            let best = tokens
                .iter()
                .find(|t| t.reader_name().to_lowercase().contains("yubi"))
                .unwrap_or(&tokens[0])
                .clone();
            eprintln!(
                "{} Headless token resolution: auto-selected '{}'",
                "[ciphervault]".bold().cyan(),
                best.reader_name().yellow()
            );
            best
        }
    };

    let resolved_pin = if let Some(p) = pin_arg {
        Some(p.as_bytes().to_vec())
    } else if let Some(cached) = selected_token.get_pin() {
        Some(cached)
    } else if let Some(cached) = ciphervault_crypto::get_cached_pin() {
        Some(cached)
    } else if !headless && std::io::stdin().is_terminal() {
        if let Ok(prompted) =
            rpassword::prompt_password("Enter hardware token PIN (or press Enter to skip): ")
        {
            let trimmed = prompted.trim();
            if !trimmed.is_empty() {
                Some(trimmed.as_bytes().to_vec())
            } else {
                None
            }
        } else {
            None
        }
    } else {
        None
    };

    if let Some(pin) = resolved_pin {
        selected_token.set_pin(&pin);
        if let Err(e) = selected_token.verify_pin(&pin) {
            bail!("Hardware token PIN authentication failed: {}", e);
        }
    }

    Ok(selected_token)
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

fn ensure_file_in_gitignore(rel_path: &Path) -> Result<bool> {
    let gitignore_path = Path::new(".gitignore");
    let norm = rel_path.to_string_lossy().replace('\\', "/");
    let target = norm.trim_start_matches("./");

    let existing = if gitignore_path.exists() {
        fs::read_to_string(gitignore_path)?
    } else {
        String::new()
    };

    for line in existing.lines() {
        let trimmed = line.trim().replace('\\', "/");
        if trimmed == target || trimmed == format!("/{}", target) {
            return Ok(false);
        }
        if trimmed.ends_with('*') {
            let prefix = trimmed.trim_end_matches('*');
            if target.starts_with(prefix) {
                return Ok(false);
            }
        }
    }

    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(gitignore_path)?;

    if !existing.ends_with('\n') && !existing.is_empty() {
        file.write_all(b"\n")?;
    }
    writeln!(file, "{}", target)?;
    Ok(true)
}

fn is_secret_pattern(pattern: &str) -> bool {
    let lower = pattern.to_lowercase();
    let name = pattern.rsplit('/').next().unwrap_or(pattern).to_lowercase();

    if lower.contains("node_modules")
        || lower.contains("target")
        || lower.contains("dist")
        || lower.contains("build")
        || lower.contains("vendor")
        || lower.contains(".next")
        || lower.contains(".cache")
        || lower.contains(".git")
        || lower.contains(".ciphervault")
        || lower.contains("coverage")
        || lower.contains("__pycache__")
        || lower.ends_with(".log")
        || lower.ends_with(".lock")
        || lower == ".ds_store"
        || lower == "thumbs.db"
    {
        return false;
    }

    if name.ends_with(".key")
        || name.ends_with(".pem")
        || name.ends_with(".crt")
        || name.ends_with(".pfx")
        || name.ends_with(".p12")
        || name.ends_with(".asc")
    {
        return true;
    }

    if name.starts_with(".env") || name.contains(".env.") || name == ".env" {
        return true;
    }

    if name.contains("secret")
        || name.contains("credential")
        || name.contains("token")
        || name.contains("password")
        || name.contains("seed")
        || name.contains("id_rsa")
        || name.contains("id_ed25519")
        || name.contains("keystore")
    {
        return true;
    }

    false
}

fn scan_gitignore_for_secrets(root_dir: &Path) -> Result<Vec<PathBuf>> {
    let gitignore_path = root_dir.join(".gitignore");
    if !gitignore_path.exists() {
        return Ok(Vec::new());
    }

    let content = fs::read_to_string(gitignore_path)?;
    let mut candidate_patterns = Vec::new();

    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let clean = trimmed.trim_start_matches('/').trim_start_matches("./");
        if is_secret_pattern(clean) {
            candidate_patterns.push(clean.to_string());
        }
    }

    let mut discovered = std::collections::BTreeSet::new();

    for pat in &candidate_patterns {
        if !pat.contains('*') {
            let p = PathBuf::from(pat);
            let full = root_dir.join(&p);
            if full.is_file() || (!full.exists() && is_secret_pattern(pat)) {
                discovered.insert(p);
            }
        }
    }

    for entry in walkdir::WalkDir::new(root_dir)
        .max_depth(4)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if entry.file_type().is_dir() {
            continue;
        }
        let rel = match entry.path().strip_prefix(root_dir) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rel_norm = rel.to_string_lossy().replace('\\', "/");

        if rel_norm.starts_with(".ciphervault")
            || rel_norm.starts_with(".git")
            || rel_norm.starts_with("target")
            || rel_norm.starts_with("node_modules")
            || rel_norm.starts_with("dist")
        {
            continue;
        }

        for pat in &candidate_patterns {
            let pat_norm = pat.replace('\\', "/");
            let is_match = if pat_norm.contains('*') {
                let parts: Vec<&str> = pat_norm.split('*').collect();
                if parts.len() == 2 {
                    rel_norm.starts_with(parts[0]) && rel_norm.ends_with(parts[1])
                } else {
                    rel_norm.contains(pat_norm.trim_matches('*'))
                }
            } else {
                rel_norm == pat_norm
            };

            if is_match {
                discovered.insert(rel.to_path_buf());
            }
        }
    }

    Ok(discovered.into_iter().collect())
}

async fn cmd_watch(debounce_secs: u64, sync: bool) -> Result<()> {
    let root_dir = std::env::current_dir()?;
    let vault_db = root_dir.join(VAULT_DIR).join(DB_FILE);
    if !vault_db.exists() {
        bail!(
            "No CipherVault found in current directory ({}). Run '{}' first.",
            root_dir.display(),
            "ciphervault init".cyan()
        );
    }

    let operators = if sync {
        get_configured_operators()
    } else {
        Vec::new()
    };

    println!(
        "{}",
        "================================================================================".cyan()
    );
    println!(
        "{}",
        "        CIPHERVAULT AUTONOMOUS FILE WATCHER DAEMON (EVENT-DRIVEN)"
            .bold()
            .green()
    );
    println!(
        "{}",
        "================================================================================".cyan()
    );
    println!(
        "  Vault Root:    {}",
        root_dir.display().to_string().yellow()
    );
    println!(
        "  Debounce:      {} second(s)",
        debounce_secs.to_string().cyan()
    );
    println!(
        "  Remote Sync:   {}",
        if sync {
            format!("Enabled ({} operators)", operators.len())
                .green()
                .bold()
        } else {
            "Disabled (local snapshots only; use --sync to push)".yellow()
        }
    );
    if sync {
        for op in &operators {
            println!("    - {}", op.dimmed());
        }
    }
    println!();
    println!(
        "{}",
        "Listening for save events on tracked confidential files... (Press Ctrl+C to stop)"
            .dimmed()
    );
    println!();

    let config = ciphervault_agent::WatcherConfig {
        root_dir,
        debounce: std::time::Duration::from_secs(debounce_secs),
        replicate_remote: sync,
        operators,
    };

    let watcher = ciphervault_agent::VaultWatcher::new(config)?;
    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!(
                "\n{}",
                "Received interrupt signal (Ctrl+C). Shutting down watcher...".yellow()
            );
            let _ = shutdown_tx.send(());
        }
    });

    watcher.run_loop(shutdown_rx).await
}

pub const DEFAULT_PRODUCTION_OPERATORS: &[&str] = &[
    "https://vault.cipherv.online/op/1",
    "https://vault.cipherv.online/op/2",
    "https://vault.cipherv.online/op/3",
];

pub fn mask_operator_endpoint(endpoint: &str) -> String {
    let ep = endpoint.trim_end_matches('/');
    if ep.ends_with("/op/1") || ep.contains("136.65.43.84") || ep.contains("10.128.0.39") {
        "https://vault.cipherv.online/op/1".to_string()
    } else if ep.ends_with("/op/2") || ep.contains("34.9.157.167") || ep.contains("10.128.0.40") {
        "https://vault.cipherv.online/op/2".to_string()
    } else if ep.ends_with("/op/3") || ep.contains("34.73.53.40") || ep.contains("10.142.0.2") {
        "https://vault.cipherv.online/op/3".to_string()
    } else if let Some(stripped) = ep
        .strip_prefix("http://")
        .or_else(|| ep.strip_prefix("https://"))
    {
        let host_port = stripped.split('/').next().unwrap_or(stripped);
        let host = host_port.split(':').next().unwrap_or(host_port);
        let parts: Vec<&str> = host.split('.').collect();
        if parts.len() == 4
            && parts
                .iter()
                .all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        {
            let port_suffix = if host_port.contains(':') {
                format!(":{}", host_port.split(':').nth(1).unwrap_or(""))
            } else {
                String::new()
            };
            format!(
                "Operator ({}.***.***.{}){}",
                parts[0], parts[3], port_suffix
            )
        } else {
            endpoint.to_string()
        }
    } else {
        endpoint.to_string()
    }
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
    DEFAULT_PRODUCTION_OPERATORS
        .iter()
        .map(|s| s.to_string())
        .collect()
}

/// Returns the public collector's endpoint/region pairs. Operators can be
/// grouped with `CIPHERVAULT_OPERATOR_REGIONS` using
/// `region=url1,url2;other-region=url3`. When unset, the legacy operator list
/// remains in a single `default` region.
fn get_configured_operator_regions() -> Vec<(String, String)> {
    if let Ok(raw) = std::env::var("CIPHERVAULT_OPERATOR_REGIONS") {
        let mut pairs = Vec::new();
        for entry in raw.split(';') {
            let Some((region, endpoints)) = entry.split_once('=') else {
                continue;
            };
            let region = region.trim();
            if region.is_empty() {
                continue;
            }
            for endpoint in endpoints
                .split([',', ' '])
                .map(str::trim)
                .filter(|endpoint| !endpoint.is_empty())
            {
                pairs.push((endpoint.to_string(), region.to_string()));
            }
        }
        if !pairs.is_empty() {
            return pairs;
        }
    }
    get_configured_operators()
        .into_iter()
        .map(|endpoint| (endpoint, "default".to_string()))
        .collect()
}

fn operator_service_request(request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
    match std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN") {
        Ok(token) if !token.is_empty() => request.header("X-CipherVault-Service-Token", token),
        _ => request,
    }
}

fn cmd_init(
    force: bool,
    custom_operators: Option<Vec<String>>,
    save_kit: Option<PathBuf>,
    hardware_token: bool,
    import_gitignore: bool,
    reader: Option<String>,
    pin: Option<String>,
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
        let token = resolve_hardware_token(reader.as_deref(), pin.as_deref(), false)?;
        println!(
            "  Detected token on reader: {}",
            token.reader_name().yellow().bold()
        );
        let pk = token.get_public_key(ciphervault_crypto::HsmSlot::DigitalSignature)?;
        println!(
            "  Bound to PIV Slot 9C Public Key: {}",
            hex::encode(&pk).green()
        );
        let _ = save_token_reader_preference(token.reader_name());
        let sk = generate_signing_key();
        (sk, pk)
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
        DEFAULT_PRODUCTION_OPERATORS
            .iter()
            .map(|s| s.to_string())
            .collect()
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

    // Smart .gitignore secret discovery
    if let Ok(discovered_secrets) = scan_gitignore_for_secrets(Path::new(".")) {
        if !discovered_secrets.is_empty() {
            let should_import = if import_gitignore {
                true
            } else if std::io::stdin().is_terminal() {
                println!();
                println!("{}", "--------------------------------------------------------------------------------".cyan());
                println!(
                    "{}",
                    "  [GITIGNORE SCAN] Discovered Confidential Files in .gitignore:"
                        .bold()
                        .green()
                );
                println!("{}", "--------------------------------------------------------------------------------".cyan());
                for s in &discovered_secrets {
                    let size_str = if s.exists() {
                        if let Ok(meta) = s.metadata() {
                            format!(" [found: {} bytes]", meta.len()).green()
                        } else {
                            " [found]".green()
                        }
                    } else {
                        " [planned]".yellow()
                    };
                    println!("    - {} {}", s.display().to_string().yellow(), size_str);
                }
                println!(
                    "{}",
                    "    (Build folders node_modules/, target/, dist/, *.log were excluded)"
                        .dimmed()
                );
                println!();
                print!("Track these confidential secret file(s) in CipherVault now? [Y/n]: ");
                let _ = std::io::stdout().flush();
                let mut ans = String::new();
                if std::io::stdin().read_line(&mut ans).is_ok() {
                    let trimmed = ans.trim().to_lowercase();
                    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
                } else {
                    false
                }
            } else {
                false
            };

            if should_import {
                println!();
                println!(
                    "{}",
                    "Registering secrets discovered in .gitignore:"
                        .bold()
                        .cyan()
                );
                for s in discovered_secrets {
                    let path_str = s.to_string_lossy();
                    let file_id = store.track_file(&path_str)?;
                    println!(
                        "  {} {} (ID: {})",
                        "+".green(),
                        path_str.yellow(),
                        hex::encode(&file_id[0..4]).dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}

fn cmd_track(mut paths: Vec<PathBuf>, from_gitignore: bool, no_gitignore: bool) -> Result<()> {
    let store = get_vault_store()?;

    if from_gitignore {
        let discovered = scan_gitignore_for_secrets(Path::new("."))?;
        if discovered.is_empty() {
            println!(
                "{}",
                "No confidential secret files discovered in .gitignore.".yellow()
            );
        } else {
            println!(
                "{} Discovered {} secret file(s) in .gitignore.",
                "[GITIGNORE]".bold().cyan(),
                discovered.len()
            );
            for p in discovered {
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }

    if paths.is_empty() {
        bail!(
            "No files specified to track.\nProvide paths (e.g. 'ciphervault track .env') or use 'ciphervault track --from-gitignore'."
        );
    }

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

        if !no_gitignore {
            if let Ok(added) = ensure_file_in_gitignore(&path) {
                if added {
                    println!(
                        "    ↳ {}",
                        format!(
                            "Appended '{}' to .gitignore to prevent accidental git leaks",
                            path_str
                        )
                        .dimmed()
                    );
                }
            }
        }
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
        println!("  - {}", mask_operator_endpoint(&op).cyan());
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

pub async fn cmd_push(
    message: Option<String>,
    touch: bool,
    local: bool,
    anchor: bool,
    reader: Option<String>,
    pin: Option<String>,
) -> Result<()> {
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
        let token = resolve_hardware_token(reader.as_deref(), pin.as_deref(), false)?;
        println!("  Found token on reader: {}", token.reader_name().cyan());
        Some(token)
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

    if local {
        println!(
            "  Durability:     {} (offline / local-only commit)",
            "LocalOnly".yellow().bold()
        );
        return Ok(());
    }

    // Attempt multi-operator replication
    let operators = get_configured_operators();
    println!(
        "\nReplicating across {} independent operators...",
        operators.len()
    );

    let pool = configured_operator_pool(operators.clone());

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

    if anchor {
        println!(
            "{}",
            "Triggering automated post-push Arbitrum L2 anchoring...".cyan()
        );
        if let Err(e) = cmd_anchor(None, None, None, None, None, None, true, None).await {
            eprintln!("{}: {}", "Notice: Post-push anchoring failed".yellow(), e);
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

fn cmd_restore(
    snapshot_hex_opt: Option<String>,
    to_dir_opt: Option<PathBuf>,
    hardware_token: bool,
    reader_opt: Option<String>,
    pin_opt: Option<String>,
) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

    let certs = store.list_device_certificates()?;
    let is_hardware_bound = certs
        .first()
        .map(|c| c.device_signing_pk != device_sk.verifying_key().to_bytes())
        .unwrap_or(false);

    if hardware_token || is_hardware_bound {
        println!("{}", "Hardware Token Authentication:".bold().cyan());
        let token = resolve_hardware_token(
            reader_opt.as_deref(),
            pin_opt.as_deref(),
            !std::io::stdin().is_terminal(),
        )?;
        println!(
            "  ✓ Hardware Key Verified: {} (Slot 9C/9D authenticated)",
            token.reader_name().green()
        );
    }

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

async fn cmd_run(
    snapshot_hex_opt: Option<String>,
    env_file_opt: Option<String>,
    no_inherit: bool,
    dry_run: bool,
    quiet: bool,
    set_overrides: Option<Vec<String>>,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified to execute. Usage: ciphervault run [OPTIONS] -- <COMMAND> [ARGS]...");
    }

    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

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
                .context("Vault has no snapshots committed yet. Create a snapshot first with 'ciphervault push'")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

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

    let mut chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        // Attempt to fetch missing chunks from configured operators
        let existing_cids: std::collections::HashSet<[u8; 32]> =
            chunks.iter().filter_map(|c| c.compute_cid().ok()).collect();
        let missing_cids: Vec<[u8; 32]> = needed_cids
            .iter()
            .copied()
            .filter(|cid| !existing_cids.contains(cid))
            .collect();

        let operators = get_configured_operators();
        if !operators.is_empty() {
            let pool = configured_operator_pool(operators);
            for cid in &missing_cids {
                if let Ok(bytes) = pool.fetch_object_from_any(cid).await {
                    if let Ok(chunk) = from_canonical_cbor::<ChunkWireObject>(&bytes) {
                        chunks.push(chunk);
                    }
                }
            }
        }

        if chunks.len() != needed_cids.len() {
            bail!(
                "Cannot execute: missing {} encrypted chunk(s) across local store and operators",
                needed_cids.len() - chunks.len()
            );
        }
    }

    // Decrypt snapshot files strictly in volatile memory (zero disk exposure)
    let mut decrypted_files = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;

    // Select which file(s) to load environment variables from
    let mut loaded_vars: Vec<(String, String)> = Vec::new();
    let mut loaded_from_files: Vec<String> = Vec::new();

    if let Some(target_file) = env_file_opt {
        let norm_target = target_file.replace('\\', "/");
        let matched = decrypted_files
            .iter()
            .find(|f| f.relative_path.replace('\\', "/") == norm_target);

        match matched {
            Some(file) => {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(parsed);
            }
            None => {
                bail!(
                    "Specified env file '{}' not found in snapshot {}",
                    target_file,
                    &hex::encode(snapshot_id)[..12]
                );
            }
        }
    } else {
        // Auto-detect .env files: load .env first, then other .env.* files
        let mut env_files: Vec<&ciphervault_snapshot::DecryptedFile> = decrypted_files
            .iter()
            .filter(|f| {
                let p = f.relative_path.replace('\\', "/");
                let name = p.rsplit('/').next().unwrap_or(&p);
                name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
            })
            .collect();

        // Sort so that .env is base and .env.local / .env.production override earlier keys
        env_files.sort_by_key(|f| {
            let p = f.relative_path.replace('\\', "/");
            let name = p.rsplit('/').next().unwrap_or(&p);
            if name == ".env" {
                0
            } else {
                1
            }
        });

        if env_files.is_empty() {
            if !quiet {
                eprintln!(
                    "{}",
                    "⚠️  No .env files found in snapshot; running with existing environment only."
                        .yellow()
                );
            }
        } else {
            for file in env_files {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(parsed);
            }
        }
    }

    // Apply additional --set overrides
    if let Some(overrides) = set_overrides {
        for item in overrides {
            if let Some((k, v)) = item.split_once('=') {
                loaded_vars.push((k.trim().to_string(), v.to_string()));
            } else {
                bail!("Invalid --set format: expected KEY=VALUE, got '{}'", item);
            }
        }
    }

    // Cleanly deduplicate keys, keeping the last definition
    let mut deduped_vars: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (k, v) in loaded_vars {
        deduped_vars.insert(k, v);
    }

    // Dry Run Mode
    if dry_run {
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "  {}",
            "CipherVault Zero-Disk Secret Injection (Dry Run)"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("Snapshot: {}", hex::encode(snapshot_id)[..12].yellow());
        println!("Sources:  {}", loaded_from_files.join(", ").cyan());
        println!(
            "Secrets:  {} variable(s) ready for injection",
            deduped_vars.len()
        );
        println!();
        for k in deduped_vars.keys() {
            println!("  • {} = [REDACTED]", k.bold().white());
        }
        println!();
        println!(
            "{}",
            "✓ Zero secrets written to disk. Exiting without execution.".green()
        );

        // Zeroize memory buffers
        for f in &mut decrypted_files {
            f.plaintext.zeroize();
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    fn resolve_windows_command(exe: &str) -> (String, Vec<String>) {
        let p = Path::new(exe);
        if p.extension().is_some() || exe.contains('\\') || exe.contains('/') {
            return (exe.to_string(), Vec::new());
        }

        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        let extensions: Vec<&str> = pathext.split(';').filter(|s| !s.is_empty()).collect();

        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                for ext in &extensions {
                    let candidate = dir.join(format!("{}{}", exe, ext));
                    if candidate.is_file() {
                        let ext_upper = ext.to_uppercase();
                        if ext_upper == ".CMD" || ext_upper == ".BAT" {
                            return (
                                "cmd.exe".to_string(),
                                vec!["/c".to_string(), candidate.to_string_lossy().to_string()],
                            );
                        }
                        return (candidate.to_string_lossy().to_string(), Vec::new());
                    }
                }
            }
        }

        (exe.to_string(), Vec::new())
    }

    // Configure Child Command
    let exe = &command[0];
    let raw_args = &command[1..];

    #[cfg(target_os = "windows")]
    let (target_bin, prefix_args) = resolve_windows_command(exe);
    #[cfg(not(target_os = "windows"))]
    let (target_bin, prefix_args): (String, Vec<String>) = (exe.clone(), Vec::new());

    let mut cmd = std::process::Command::new(&target_bin);
    if !prefix_args.is_empty() {
        cmd.args(&prefix_args);
    }
    cmd.args(raw_args);

    if no_inherit {
        cmd.env_clear();
        // Retain essential operating system paths so standard binaries and runtimes function
        for (k, v) in std::env::vars() {
            let k_upper = k.to_uppercase();
            if k_upper == "PATH"
                || k_upper == "SYSTEMROOT"
                || k_upper == "TEMP"
                || k_upper == "TMP"
                || k_upper == "USERPROFILE"
                || k_upper == "HOME"
                || k_upper == "COMSPEC"
                || k_upper == "PATHEXT"
            {
                cmd.env(k, v);
            }
        }
    }

    // Inject decrypted secrets
    for (k, v) in &deduped_vars {
        cmd.env(k, v);
    }

    if !quiet {
        eprintln!(
            "{} Injected {} secret(s) from snapshot {} into '{}'",
            "[ciphervault]".bold().cyan(),
            deduped_vars.len().to_string().bold().green(),
            hex::encode(snapshot_id)[..8].yellow(),
            exe.white()
        );
    }

    // Zeroize decrypted memory buffers prior to child process execution
    for f in &mut decrypted_files {
        f.plaintext.zeroize();
    }

    // Spawn child process with inherited stdio
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", exe))?;

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait on child process '{}'", exe))?;

    let exit_code = status.code().unwrap_or(1);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

fn cmd_completions(shell: clap_complete::Shell) {
    let mut cmd = Cli::command();
    clap_complete::generate(shell, &mut cmd, "ciphervault", &mut std::io::stdout());
}

pub fn generate_diff_report(
    snapshot_a_opt: Option<String>,
    snapshot_b_opt: Option<String>,
    file_filter_opt: Option<String>,
    reveal: bool,
) -> Result<diff::DiffReport> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

    // Helper to decrypt snapshot files into a map of (relative_path -> Vec<u8>)
    let decrypt_snap = |snap_id: &[u8; 32]| -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let (record, encrypted_manifest) = store.get_snapshot(snap_id)?;
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
        let files = decrypt_snapshot(
            &vault_id,
            &epoch_key,
            record.epoch,
            &encrypted_manifest,
            &chunks,
        )?;

        let mut map = std::collections::BTreeMap::new();
        for f in files {
            map.insert(f.relative_path.replace('\\', "/"), f.plaintext);
        }
        Ok(map)
    };

    let parse_snap_id = |s: &str| -> Result<[u8; 32]> {
        let bytes = hex::decode(s.trim())?;
        if bytes.len() != 32 {
            bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    };

    let read_working_tree = || -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut map = std::collections::BTreeMap::new();
        if let Ok(tracked) = store.list_tracked_files() {
            for (p, _) in tracked {
                let rel_str = p.display().to_string().replace('\\', "/");
                if p.exists() {
                    if let Ok(data) = fs::read(&p) {
                        map.insert(rel_str, data);
                    }
                }
            }
        }
        map
    };

    let get_head_cid = || -> Result<[u8; 32]> {
        let head = store.get_active_head()?.context(
            "Vault has no snapshots committed yet. Create a snapshot first with 'ciphervault push'",
        )?;
        if head.snapshot_id.len() != 32 {
            bail!("Invalid snapshot ID length in active head");
        }
        let mut head_cid = [0u8; 32];
        head_cid.copy_from_slice(&head.snapshot_id);
        Ok(head_cid)
    };

    let snap_a_clean = snapshot_a_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let snap_b_clean = snapshot_b_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (old_label, new_label, old_files, new_files) =
        match (snap_a_clean.as_deref(), snap_b_clean.as_deref()) {
            (None, None)
            | (Some("head"), None)
            | (Some("head"), Some("working"))
            | (None, Some("working")) => {
                let head_cid = get_head_cid()?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = read_working_tree();
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    "working tree".to_string(),
                    old_map,
                    new_map,
                )
            }
            (Some("working"), Some("head")) => {
                let head_cid = get_head_cid()?;
                let old_map = read_working_tree();
                let new_map = decrypt_snap(&head_cid)?;
                (
                    "working tree".to_string(),
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), None) | (Some(a_str), Some("working")) => {
                let a_id = parse_snap_id(a_str)?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = read_working_tree();
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    "working tree".to_string(),
                    old_map,
                    new_map,
                )
            }
            (Some("working"), Some(b_str)) => {
                let b_id = parse_snap_id(b_str)?;
                let old_map = read_working_tree();
                let new_map = decrypt_snap(&b_id)?;
                (
                    "working tree".to_string(),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some("head"), Some(b_str)) => {
                let head_cid = get_head_cid()?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), Some("head")) => {
                let a_id = parse_snap_id(a_str)?;
                let head_cid = get_head_cid()?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = decrypt_snap(&head_cid)?;
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), Some(b_str)) => {
                let a_id = parse_snap_id(a_str)?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (None, Some(b_str)) => {
                let head_cid = get_head_cid()?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
        };

    let mut report = diff::DiffReport::new(old_label, new_label);

    // Collect union of file paths
    let mut all_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in old_files.keys() {
        all_paths.insert(p.clone());
    }
    for p in new_files.keys() {
        all_paths.insert(p.clone());
    }

    for path in all_paths {
        if let Some(ref filter) = file_filter_opt {
            let norm_filter = filter.replace('\\', "/");
            if path != norm_filter && !path.ends_with(&format!("/{}", norm_filter)) {
                continue;
            }
        }

        let old_bytes = old_files.get(&path).cloned().unwrap_or_default();
        let new_bytes = new_files.get(&path).cloned().unwrap_or_default();

        let is_dotenv_file = {
            let name = path.rsplit('/').next().unwrap_or(&path);
            name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
        };

        if is_dotenv_file {
            let old_vars = dotenv::parse_dotenv_bytes(&old_bytes).unwrap_or_default();
            let new_vars = dotenv::parse_dotenv_bytes(&new_bytes).unwrap_or_default();
            let file_rep = diff::diff_dotenv(&path, &old_vars, &new_vars, reveal);
            report.add_file_report(file_rep);
        } else {
            let old_str = String::from_utf8_lossy(&old_bytes);
            let new_str = String::from_utf8_lossy(&new_bytes);
            let file_rep = diff::diff_text(&path, &old_str, &new_str, reveal);
            report.add_file_report(file_rep);
        }
    }

    Ok(report)
}

fn cmd_diff(
    snapshot_a_opt: Option<String>,
    snapshot_b_opt: Option<String>,
    file_filter_opt: Option<String>,
    reveal: bool,
    json_output: bool,
) -> Result<()> {
    let report = generate_diff_report(snapshot_a_opt, snapshot_b_opt, file_filter_opt, reveal)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        diff::print_diff_report(&report);
    }
    Ok(())
}

async fn cmd_pull(dry_run: bool, force: bool) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, local_epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(local_epoch)?;
    let (recovery_signing_pk, _, locator) = store.get_recovery_descriptors()?;

    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured. Cannot pull from remote federation.");
    }

    println!(
        "Connecting to {} independent storage operator(s)...",
        operators.len()
    );
    let pool = configured_operator_pool(operators);

    let raw_records = pool.query_recovery_records(&locator).await;
    if raw_records.is_empty() {
        bail!("No recovery records found on any surviving operator for this vault locator.");
    }

    let (chosen_head, certificate) =
        ciphervault_recovery::trust::select_head(&raw_records, &vault_id, &recovery_signing_pk)?;

    let local_head = store.get_active_head()?;
    if let Some(lh) = &local_head {
        let any_missing = store
            .list_tracked_files()
            .unwrap_or_default()
            .iter()
            .any(|(p, _)| !p.exists());
        if lh.snapshot_id == chosen_head.snapshot_id && !force && !any_missing {
            println!(
                "{}",
                format!(
                    "✓ Already up to date with operator cluster (Head: {})",
                    hex::encode(&lh.snapshot_id)[..12].yellow()
                )
                .green()
            );
            return Ok(());
        }
    }

    let mut snap_cid = [0u8; 32];
    snap_cid.copy_from_slice(&chosen_head.snapshot_id);

    if let Some(lh) = &local_head {
        if lh.snapshot_id == chosen_head.snapshot_id {
            println!(
                "Syncing confidential files from remote snapshot: {}",
                hex::encode(snap_cid)[..12].yellow()
            );
        } else {
            println!(
                "Found newer remote snapshot: {}",
                hex::encode(snap_cid)[..12].yellow()
            );
        }
    } else {
        println!(
            "Found remote snapshot: {}",
            hex::encode(snap_cid)[..12].yellow()
        );
    }

    if dry_run {
        println!(
            "{}",
            "✓ Dry run complete: updates are available from operators. Run 'ciphervault pull' to apply."
                .green()
        );
        return Ok(());
    }

    // Safety guard against uncommitted local modifications unless --force
    if !force {
        let tracked = store.list_tracked_files()?;
        let mut dirty_files = Vec::new();
        for (rel_path, orig_hash) in &tracked {
            if rel_path.exists() {
                if let Ok(bytes) = fs::read(rel_path) {
                    use sha2::Digest;
                    let cur_hash = sha2::Sha256::digest(&bytes);
                    if cur_hash.as_slice() != orig_hash.as_slice() {
                        dirty_files.push(rel_path.display().to_string());
                    }
                }
            }
        }
        if !dirty_files.is_empty() {
            bail!(
                "Local tracked file(s) have uncommitted modifications: {}\nCommit changes with 'ciphervault push' or discard with 'ciphervault pull --force'",
                dirty_files.join(", ")
            );
        }
    }

    // Fetch and authenticate snapshot record object
    let snap_record_bytes = pool.fetch_object_from_any(&snap_cid).await?;
    let record: SnapshotRecord = from_canonical_cbor(&snap_record_bytes)?;
    ciphervault_recovery::trust::verify_snapshot(&record, &chosen_head, &certificate)?;

    // Fetch encrypted manifest
    let mut manifest_cid = [0u8; 32];
    manifest_cid.copy_from_slice(&record.encrypted_manifest_cid);
    let encrypted_manifest = pool.fetch_object_from_any(&manifest_cid).await?;

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

    // Download any missing chunk objects from operators
    let mut all_chunks = Vec::new();
    let mut missing_cids = Vec::new();

    for file in &manifest.files {
        if file.is_deleted {
            continue;
        }
        for cid_bytes in &file.chunk_cids {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cid_bytes);
            missing_cids.push(arr);
        }
    }

    let local_chunks = store.get_chunks(&missing_cids).unwrap_or_default();
    let local_chunk_map: std::collections::HashMap<[u8; 32], ChunkWireObject> = local_chunks
        .into_iter()
        .filter_map(|c| c.compute_cid().ok().map(|cid| (cid, c)))
        .collect();

    for cid in &missing_cids {
        if let Some(local_c) = local_chunk_map.get(cid) {
            all_chunks.push(local_c.clone());
        } else {
            let chunk_bytes = pool.fetch_object_from_any(cid).await?;
            let chunk: ChunkWireObject = from_canonical_cbor(&chunk_bytes)?;
            all_chunks.push(chunk);
        }
    }

    // Atomically restore the updated files into the current workspace
    println!("Applying updated confidential files into workspace...");
    let restored = restore_snapshot(
        &PathBuf::from("."),
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &all_chunks,
    )?;

    // Ensure pulled files are tracked in local store
    for file in &manifest.files {
        if !file.is_deleted {
            let _ = store.track_file(&file.relative_path);
        }
    }

    // Persist snapshot record, encrypted manifest, and chunks in local database
    store.save_snapshot(&record, &encrypted_manifest, &all_chunks)?;

    // Advance local head to the verified remote head
    store.set_head(&chosen_head)?;

    println!(
        "{}",
        format!(
            "✓ Successfully synchronized with operator cluster (Head: {})",
            hex::encode(snap_cid)[..12].yellow()
        )
        .bold()
        .green()
    );
    for p in restored {
        println!("  - Updated: {}", p.display().to_string().cyan());
    }

    Ok(())
}

async fn cmd_recover(
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

async fn cmd_peers(discover: bool) -> Result<()> {
    let mut operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured. Run 'ciphervault init' first.");
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

async fn cmd_approve_list() -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    println!(
        "{}",
        "Pending Out-of-Band Cryptographic Authorization Challenges".bold()
    );
    println!("---------------------------------------------------------------------------------");

    let mut all_challenges = Vec::new();
    for op in &operators {
        let url = format!("{}/v1/auth/challenges/pending", op.trim_end_matches('/'));
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(challenges) = resp
                .json::<Vec<ciphervault_recovery::ApprovalChallenge>>()
                .await
            {
                for c in challenges {
                    if !all_challenges
                        .iter()
                        .any(|x: &ciphervault_recovery::ApprovalChallenge| {
                            x.challenge_id == c.challenge_id
                        })
                    {
                        all_challenges.push(c);
                    }
                }
            }
        }
    }

    if all_challenges.is_empty() {
        println!(
            "{}",
            "  (No pending authorization challenges found across cluster)".dimmed()
        );
        return Ok(());
    }

    println!(
        "{:<20} {:<18} {:<14} {:<10} {:<24}",
        "CHALLENGE ID", "ACTION", "VAULT ID", "TTL", "DETAILS"
    );
    println!(
        "{:<20} {:<18} {:<14} {:<10} {:<24}",
        "------------------",
        "----------------",
        "------------",
        "--------",
        "----------------------"
    );

    let now = chrono::Utc::now().timestamp() as u64;
    for c in &all_challenges {
        let remaining_secs = c.expires_at_utc.saturating_sub(now);
        let ttl_str = format!("{}s", remaining_secs);
        let short_vault = if c.vault_id_hex.len() >= 8 {
            &c.vault_id_hex[..8]
        } else {
            &c.vault_id_hex
        };
        let action_str = format!("{:?}", c.action);
        println!(
            "{:<20} {:<18} {:<14} {:<10} {:<24}",
            c.challenge_id.cyan().bold(),
            action_str.yellow(),
            short_vault.dimmed(),
            ttl_str.green(),
            c.details
        );
    }

    println!();
    println!(
        "To approve a challenge, run: {}",
        "ciphervault approve sign <CHALLENGE_ID>".cyan()
    );
    Ok(())
}

async fn cmd_approve_sign(challenge_id: String, approver_name: Option<String>) -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    // 1. Fetch challenge details from operator cluster
    let mut found_challenge: Option<ciphervault_recovery::ApprovalChallenge> = None;
    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Ok(c) = serde_json::from_value::<ciphervault_recovery::ApprovalChallenge>(
                    json["challenge"].clone(),
                ) {
                    found_challenge = Some(c);
                    break;
                }
            }
        }
    }

    let challenge = found_challenge.context(format!(
        "Challenge '{}' not found or already expired on operator cluster",
        challenge_id
    ))?;

    println!("{}", "Authorize Cryptographic Approval Challenge".bold());
    println!("--------------------------------------------------");
    println!(
        "  Challenge ID:     {}",
        challenge.challenge_id.cyan().bold()
    );
    println!("  Action:           {:?}", challenge.action);
    println!("  Vault ID:         {}", challenge.vault_id_hex.yellow());
    println!("  Details:          {}", challenge.details);
    println!(
        "  Expires in:       {}s",
        challenge
            .expires_at_utc
            .saturating_sub(chrono::Utc::now().timestamp() as u64)
    );

    // Sign using device key from local store, or create an ad-hoc guardian key
    let store = get_vault_store();
    let signing_key = if let Ok(ref s) = store {
        let (_, key, _, _) = s.get_device_state()?;
        key
    } else {
        ciphervault_crypto::generate_signing_key()
    };

    let name = approver_name.unwrap_or_else(|| {
        std::env::var("USERNAME")
            .or_else(|_| std::env::var("USER"))
            .unwrap_or_else(|_| "Authorized Approver".into())
    });

    let receipt =
        ciphervault_recovery::SignedApprovalReceipt::sign(&challenge, name.clone(), &signing_key);

    // Broadcast receipt to operators
    let mut accepted_count = 0;
    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}/approve",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.post(&url))
            .json(&receipt)
            .send()
            .await
        {
            if resp.status().is_success() {
                accepted_count += 1;
            }
        }
    }

    if accepted_count == 0 {
        bail!("Failed to submit approval receipt to any operator");
    }

    println!(
        "{}",
        format!(
            "✓ Cryptographic approval signature by '{}' submitted and accepted by {} operator(s)!",
            name, accepted_count
        )
        .green()
        .bold()
    );

    Ok(())
}

async fn cmd_approve_status(challenge_id: String) -> Result<()> {
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("No operators configured.");
    }

    let http = reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .unwrap_or_default();

    for op in &operators {
        let url = format!(
            "{}/v1/auth/challenges/{}",
            op.trim_end_matches('/'),
            challenge_id
        );
        if let Ok(resp) = operator_service_request(http.get(&url)).send().await {
            if let Ok(json) = resp.json::<serde_json::Value>().await {
                if let Ok(challenge) = serde_json::from_value::<
                    ciphervault_recovery::ApprovalChallenge,
                >(json["challenge"].clone())
                {
                    println!("{}", "Approval Challenge Status".bold());
                    println!("--------------------------------------------------");
                    println!("  Challenge ID:  {}", challenge.challenge_id.cyan().bold());
                    println!("  Action:        {:?}", challenge.action);
                    println!("  Details:       {}", challenge.details);
                    let approved = json["approved"].as_bool().unwrap_or(false);
                    let count = json["receipt_count"].as_u64().unwrap_or(0);
                    println!(
                        "  Status:        {}",
                        if approved {
                            "APPROVED".green().bold()
                        } else {
                            "PENDING".yellow().bold()
                        }
                    );
                    println!("  Signatures:    {}", count);

                    if let Some(receipts) = json["receipts"].as_array() {
                        for r in receipts {
                            let name = r["approver_name"].as_str().unwrap_or("Unknown");
                            let pk = r["approver_pk_hex"].as_str().unwrap_or("");
                            let short_pk = if pk.len() >= 12 { &pk[..12] } else { pk };
                            println!(
                                "    - Signed by: {} (Key: {}...)",
                                name.cyan(),
                                short_pk.dimmed()
                            );
                        }
                    }
                    return Ok(());
                }
            }
        }
    }

    bail!("Challenge '{}' not found on any operator", challenge_id);
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
    cmd_recover(Some(kit_path), None, target_dir, false).await
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
pub async fn cmd_anchor(
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

fn load_public_feed_signing_key() -> Result<SigningKey> {
    let raw = std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX").map_err(|_| {
        anyhow::anyhow!(
            "CIPHERVAULT_PUBLIC_CHECKPOINT_SIGNING_KEY_HEX is required to publish the public feed"
        )
    })?;
    let decoded = hex::decode(raw.trim().trim_start_matches("0x"))
        .context("Public checkpoint signing key is not valid hex")?;
    if decoded.len() != 32 {
        bail!("Public checkpoint signing key must be exactly 32 bytes");
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&decoded);
    Ok(SigningKey::from_bytes(&seed))
}

fn build_public_checkpoint_feed(
    evidence: Vec<ciphervault_format::CheckpointEvidence>,
    network: String,
    signing_key: &SigningKey,
    issued_at_utc: u64,
) -> Result<PublicCheckpointFeedEnvelope> {
    if network.trim().is_empty() {
        bail!("Public checkpoint feed network label cannot be empty");
    }
    if evidence.len() > 1_000 {
        bail!("Public checkpoint feed cannot contain more than 1,000 records");
    }

    let checkpoints = evidence
        .into_iter()
        .map(|record| {
            if record.version != ciphervault_format::PROTOCOL_VERSION {
                bail!("Checkpoint evidence uses an unsupported protocol version");
            }
            if !record.verify_commitment() {
                bail!("Checkpoint evidence contains an invalid commitment preimage");
            }
            if record.chain_id == 0
                || record.contract_address.len() != 20
                || record.commitment.len() != 32
                || record.head_record_cid.len() != 32
            {
                bail!("Checkpoint evidence contains invalid chain or digest lengths");
            }

            let tx_present =
                record.tx_hash.len() == 32 && record.tx_hash.iter().any(|byte| *byte != 0);
            if !record.tx_hash.is_empty() && record.tx_hash.len() != 32 {
                bail!("Checkpoint evidence contains an invalid transaction hash");
            }

            Ok(PublicCheckpointFeedEntry {
                network: network.clone(),
                chain_id: record.chain_id,
                contract_address_hex: hex::encode(record.contract_address),
                commitment_hex: hex::encode(record.commitment),
                head_record_cid_hex: hex::encode(record.head_record_cid),
                tx_hash_hex: tx_present.then(|| hex::encode(record.tx_hash)),
                block_number: (record.block_number > 0).then_some(record.block_number),
                published_at_utc: record.timestamp_utc,
            })
        })
        .collect::<Result<Vec<_>>>()?;

    let unsigned = PublicCheckpointFeedUnsigned {
        version: 1,
        issued_at_utc,
        checkpoints,
    };
    let message = ciphervault_format::to_canonical_cbor(&unsigned)
        .context("Unable to canonicalize public checkpoint feed")?;
    let signature = ciphervault_crypto::signatures::sign_with_domain(
        signing_key,
        b"public_checkpoint_feed",
        &message,
    );
    Ok(PublicCheckpointFeedEnvelope {
        version: unsigned.version,
        issued_at_utc: unsigned.issued_at_utc,
        checkpoints: unsigned.checkpoints,
        publisher_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
        signature_hex: hex::encode(signature),
    })
}

fn cmd_publish_public_feed(output: PathBuf, network: String) -> Result<()> {
    let signing_key = load_public_feed_signing_key()?;
    let store = get_vault_store()?;
    let evidence = store
        .list_checkpoint_evidence()
        .context("Unable to read checkpoint evidence from the active vault")?;
    let feed = build_public_checkpoint_feed(
        evidence,
        network,
        &signing_key,
        Utc::now().timestamp().max(0) as u64,
    )?;
    let encoded = serde_json::to_vec_pretty(&feed).context("Unable to encode public feed JSON")?;

    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let temp_path = output.with_file_name(format!(
        ".{}.tmp-{}",
        output
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("public-checkpoint-feed.json"),
        std::process::id()
    ));
    fs::write(&temp_path, &encoded)?;
    let write_result = (|| -> Result<()> {
        if output.exists() {
            fs::remove_file(&output)?;
        }
        fs::rename(&temp_path, &output)?;
        Ok(())
    })();
    if write_result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    write_result?;

    println!(
        "Published {} signed checkpoint record(s) to {}",
        feed.checkpoints.len(),
        output.display()
    );
    println!(
        "Publisher verification key: {}",
        feed.publisher_key_hex.cyan()
    );
    println!(
        "Receipt and finality fields remain independently unverified until a chain verifier confirms them."
    );
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
        TokenSubcommand::Status { reader } => {
            println!(
                "{}",
                "=== CIPHERVAULT HARDWARE SECURITY MODULE & YUBIKEY STATUS ==="
                    .bold()
                    .cyan()
            );
            let readers = ciphervault_crypto::list_readers()?;
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
            match ciphervault_crypto::probe_with_reader(reader.as_deref())? {
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
        TokenSubcommand::Probe { reader } => {
            match ciphervault_crypto::probe_with_reader(reader.as_deref())? {
                Some(token) => {
                    let info_9c =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::DigitalSignature)?;
                    let info_9d =
                        token.get_slot_info(ciphervault_crypto::HsmSlot::KeyManagement)?;
                    let payload = serde_json::json!({
                        "detected": true,
                        "reader": token.reader_name(),
                        "slot_9c": info_9c,
                        "slot_9d": info_9d,
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                }
                None => {
                    let readers = ciphervault_crypto::list_readers()?;
                    let payload = serde_json::json!({
                        "detected": false,
                        "readers": readers,
                        "message": "No PIV smartcard token detected in PC/SC readers",
                    });
                    println!("{}", serde_json::to_string_pretty(&payload)?);
                }
            }
        }
        TokenSubcommand::List => {
            println!(
                "{}",
                "=== CIPHERVAULT PC/SC READERS & TOKENS ===".bold().cyan()
            );
            let readers = ciphervault_crypto::list_readers()?;
            if readers.is_empty() {
                println!("  No PC/SC card readers detected on system.");
                return Ok(());
            }
            let active_tokens = ciphervault_crypto::probe_all()?;
            let active_reader_names: std::collections::HashSet<String> = active_tokens
                .iter()
                .map(|t| t.reader_name().to_string())
                .collect();

            let preferred = get_saved_token_reader();

            for (i, r) in readers.iter().enumerate() {
                let has_piv = active_reader_names.contains(r);
                let is_pref = preferred.as_deref() == Some(r.as_str());
                let pref_str = if is_pref {
                    " [Default]".cyan().bold()
                } else {
                    "".normal()
                };
                if has_piv {
                    println!(
                        "  [{}] {} {} {}",
                        i + 1,
                        r.green().bold(),
                        "✓ PIV Ready".green(),
                        pref_str
                    );
                } else {
                    println!(
                        "  [{}] {} {} {}",
                        i + 1,
                        r.dimmed(),
                        "(No PIV card inserted)".dimmed(),
                        pref_str
                    );
                }
            }
            println!(
                "\n  Total Readers: {} | Active PIV Tokens: {}",
                readers.len(),
                active_tokens.len()
            );
        }
        TokenSubcommand::Slots { reader } => {
            println!(
                "{}",
                "=== CIPHERVAULT HARDWARE TOKEN SLOT INSPECTOR ==="
                    .bold()
                    .cyan()
            );
            let token =
                resolve_hardware_token(reader.as_deref(), None, !std::io::stdin().is_terminal())?;
            println!(
                "  Hardware Token: {}\n",
                token.reader_name().yellow().bold()
            );

            let slots = [
                (
                    ciphervault_crypto::HsmSlot::DigitalSignature,
                    "9C",
                    "Digital Signature",
                ),
                (
                    ciphervault_crypto::HsmSlot::KeyManagement,
                    "9D",
                    "Key Management / ECDH",
                ),
                (
                    ciphervault_crypto::HsmSlot::Authentication,
                    "9A",
                    "Authentication",
                ),
                (
                    ciphervault_crypto::HsmSlot::CardAuthentication,
                    "9E",
                    "Card Authentication",
                ),
            ];

            for (slot, hex_code, label) in slots {
                print!("  Slot {} ({}): ", hex_code.bold(), label);
                match token.get_slot_info(slot) {
                    Ok(info) => {
                        println!("{}", "Active".green().bold());
                        println!("    Algorithm:    {}", info.algorithm.cyan());
                        println!("    Touch Policy: {}", info.touch_policy);
                        println!("    PIN Policy:   {}", info.pin_policy);
                        println!("    Public Key:   {}", info.public_key_hex.dimmed());
                    }
                    Err(e) => {
                        println!("{} ({})", "Unprovisioned / Inaccessible".dimmed(), e);
                    }
                }
                println!();
            }
        }
        TokenSubcommand::Pin { pin, test, clear } => {
            if clear {
                ciphervault_crypto::clear_cached_pin();
                println!(
                    "{}",
                    "✓ Cleared cached hardware token PIN from session memory.".green()
                );
                return Ok(());
            }

            let pin_val = if let Some(p) = pin {
                p
            } else if std::io::stdin().is_terminal() {
                rpassword::prompt_password("Enter hardware token PIN: ")?
            } else {
                bail!("Must specify --pin <PIN> in headless/non-interactive mode");
            };

            let pin_bytes = pin_val.trim().as_bytes();
            if test {
                match ciphervault_crypto::PcscHardwareToken::probe()? {
                    Some(token) => {
                        token.verify_pin(pin_bytes)?;
                        println!(
                            "{}",
                            "✓ PIN verified successfully with attached hardware token!"
                                .bold()
                                .green()
                        );
                        ciphervault_crypto::set_cached_pin(pin_bytes);
                    }
                    None => {
                        bail!("Cannot test PIN: No PIV hardware token detected in PC/SC readers.");
                    }
                }
            } else {
                ciphervault_crypto::set_cached_pin(pin_bytes);
                println!(
                    "{}",
                    "✓ Hardware token PIN cached in volatile session memory.".green()
                );
            }
        }
        TokenSubcommand::Select { reader } => {
            let readers = ciphervault_crypto::list_readers()?;
            if readers.is_empty() {
                bail!("No PC/SC smartcard readers detected on system.");
            }

            let target = if let Some(r) = reader {
                let r_lower = r.to_lowercase();
                readers
                    .into_iter()
                    .find(|name| name.to_lowercase().contains(&r_lower))
                    .ok_or_else(|| anyhow::anyhow!("Reader matching '{}' not found", r))?
            } else if std::io::stdin().is_terminal() {
                println!(
                    "\n{}",
                    "Select default hardware token reader:".bold().cyan()
                );
                for (i, r) in readers.iter().enumerate() {
                    println!("  [{}] {}", i + 1, r.green());
                }
                print!("Selection [1-{}]: ", readers.len());
                let _ = std::io::stdout().flush();
                let mut input = String::new();
                std::io::stdin().read_line(&mut input)?;
                let choice: usize = input.trim().parse().unwrap_or(1);
                let idx = if choice >= 1 && choice <= readers.len() {
                    choice - 1
                } else {
                    0
                };
                readers[idx].clone()
            } else {
                bail!("Must provide reader name in headless mode. Usage: ciphervault token select --reader <NAME>");
            };

            save_token_reader_preference(&target)?;
            println!(
                "{} Default hardware token reader set to '{}'",
                "✓".green().bold(),
                target.yellow()
            );
        }
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
    configured_operator_pool(operators)
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

/// The embedded UI has two deliberately separate serving contexts. The local
/// workspace has access to a vault's private data and actions, while the
/// hosted server is a public explorer and must never acquire those routes by
/// accident.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum UiServerMode {
    LocalPrivate,
    PublicExplorer,
}

impl UiServerMode {
    fn access_mode(self) -> &'static str {
        match self {
            Self::LocalPrivate => "private",
            Self::PublicExplorer => "public",
        }
    }

    fn name(self) -> &'static str {
        match self {
            Self::LocalPrivate => "local_private",
            Self::PublicExplorer => "public_explorer",
        }
    }
}

#[derive(Clone)]
struct PrivateUiSessionState {
    token: String,
    vault_binding: Option<String>,
    issued_at: Instant,
}

static PRIVATE_UI_SESSION: OnceLock<RwLock<PrivateUiSessionState>> = OnceLock::new();
const PRIVATE_UI_SESSION_TTL: Duration = Duration::from_secs(30 * 60);

fn current_private_vault_binding() -> Option<String> {
    get_vault_store()
        .ok()
        .and_then(|store| store.get_vault_id().ok())
        .map(hex::encode)
}

fn new_private_ui_session(vault_binding: Option<String>) -> PrivateUiSessionState {
    let mut token_bytes = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token_bytes);
    PrivateUiSessionState {
        token: hex::encode(token_bytes),
        vault_binding,
        issued_at: Instant::now(),
    }
}

fn private_ui_session_should_rotate(
    state: &PrivateUiSessionState,
    current_binding: &Option<String>,
) -> bool {
    state.vault_binding != *current_binding || state.issued_at.elapsed() >= PRIVATE_UI_SESSION_TTL
}

fn private_ui_session_snapshot() -> PrivateUiSessionState {
    let current_binding = current_private_vault_binding();
    let session = PRIVATE_UI_SESSION
        .get_or_init(|| RwLock::new(new_private_ui_session(current_binding.clone())));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    if private_ui_session_should_rotate(&state, &current_binding) {
        *state = new_private_ui_session(current_binding);
    }
    state.clone()
}

fn revoke_private_ui_session() {
    let current_binding = current_private_vault_binding();
    let session = PRIVATE_UI_SESSION
        .get_or_init(|| RwLock::new(new_private_ui_session(current_binding.clone())));
    let mut state = session
        .write()
        .expect("private UI session lock must not be poisoned");
    *state = new_private_ui_session(current_binding);
}

fn current_account_context() -> serde_json::Value {
    let Ok(account) = AccountStore::open(None) else {
        return serde_json::json!({
            "configured": false,
            "required": false,
            "authenticated": false,
        });
    };
    let mut context = serde_json::json!({
        "configured": true,
        "account_id": account.account_id(),
        "display_name": account.record().display_name,
        "session": account.session_status(),
        // If any vault has been linked, inability to resolve the current
        // device is surfaced as an authentication requirement rather than a
        // silent accountless fallback.
        "required": !account.record().vaults.is_empty(),
    });
    if let Ok((vault_id, device_id, device_pk)) = current_device_identity() {
        let linked = account.is_vault_linked(&vault_id);
        let authenticated = account.is_authenticated_for_device(&vault_id, &device_id, &device_pk);
        if let Some(object) = context.as_object_mut() {
            object.insert("vault_id_hex".into(), serde_json::Value::String(vault_id));
            object.insert("device_id_hex".into(), serde_json::Value::String(device_id));
            object.insert(
                "device_public_key_hex".into(),
                serde_json::Value::String(device_pk),
            );
            object.insert("linked".into(), serde_json::Value::Bool(linked));
            object.insert(
                "authenticated".into(),
                serde_json::Value::Bool(authenticated),
            );
            object.insert("required".into(), serde_json::Value::Bool(linked));
        }
    }
    context
}

/// Account authentication is optional. Once a vault is linked, private API
/// calls require a live session bound to that vault's enrolled device.
fn private_account_session_valid() -> bool {
    let Ok(account) = AccountStore::open(None) else {
        return true;
    };
    let Ok((vault_id, device_id, device_pk)) = current_device_identity() else {
        // An account with linked vaults must fail closed if the local vault
        // identity cannot be read. An account with no links still preserves
        // accountless local mode.
        return account.record().vaults.is_empty();
    };
    if !account.is_vault_linked(&vault_id) {
        return true;
    }
    account.is_authenticated_for_device(&vault_id, &device_id, &device_pk)
}

fn ui_capabilities(mode: UiServerMode) -> serde_json::Value {
    let private = mode == UiServerMode::LocalPrivate;
    let hosted_account = hosted_account_endpoint().is_some();
    let public_feed_configured = std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED")
        .ok()
        .is_some_and(|path| !path.trim().is_empty());
    serde_json::json!({
        "public_operator_telemetry": true,
        // A public checkpoint publisher is opt-in. Never use a local vault
        // database as an implicit public feed.
        "public_checkpoint_metadata": !private && public_feed_configured,
        "vault_workspace": private,
        "snapshot_history": private,
        "file_inventory": private,
        "snapshot_mutation": private,
        "restore": private,
        "file_management": private,
        "recovery_ceremony": private,
        "plaintext_inspection": private,
        "workspace_switching": private,
        "fleet_audit": private,
        "hosted_account_proxy": hosted_account,
        "hosted_webauthn": hosted_account,
    })
}

fn ui_context(mode: UiServerMode) -> serde_json::Value {
    serde_json::json!({
        "mode": mode.name(),
        "access_mode": mode.access_mode(),
        "capabilities": ui_capabilities(mode),
    })
}

fn ui_shell_router() -> axum::Router {
    use axum::{http::header, response::Html, routing::get, Router};

    Router::new()
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
}

fn hosted_account_endpoint() -> Option<String> {
    let raw = std::env::var("CIPHERVAULT_ACCOUNT_ENDPOINT").ok()?;
    let endpoint = raw.trim().trim_end_matches('/');
    if endpoint.is_empty() {
        return None;
    }
    let parsed = reqwest::Url::parse(endpoint).ok()?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return None;
    }
    Some(endpoint.to_string())
}

async fn proxy_account_request(
    method: reqwest::Method,
    path: &str,
    headers: &axum::http::HeaderMap,
    body: Option<Bytes>,
) -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    let Some(endpoint) = hosted_account_endpoint() else {
        return (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_SERVICE_NOT_CONFIGURED",
                "error": "Hosted account service is not configured for this dashboard.",
            })),
        )
            .into_response();
    };
    let url = format!("{}{}", endpoint, path);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(8))
        .build()
        .unwrap_or_else(|_| reqwest::Client::new());
    let mut request = client.request(method, url);
    if let Some(cookie) = headers.get(header::COOKIE) {
        request = request.header(header::COOKIE, cookie.clone());
    }
    if let Some(authorization) = headers.get(header::AUTHORIZATION) {
        request = request.header(header::AUTHORIZATION, authorization.clone());
    }
    if let Some(content_type) = headers.get(header::CONTENT_TYPE) {
        request = request.header(header::CONTENT_TYPE, content_type.clone());
    } else if body.as_ref().is_some_and(|value| !value.is_empty()) {
        request = request.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(body) = body {
        request = request.body(body);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_SERVICE_UNAVAILABLE",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let status = axum::http::StatusCode::from_u16(response.status().as_u16())
        .unwrap_or(axum::http::StatusCode::BAD_GATEWAY);
    let content_type = response.headers().get(header::CONTENT_TYPE).cloned();
    let set_cookies = response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    let payload = match response.bytes().await {
        Ok(payload) => payload,
        Err(error) => {
            return (
                axum::http::StatusCode::BAD_GATEWAY,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_SERVICE_RESPONSE_INVALID",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let mut proxied = (status, payload).into_response();
    if let Some(content_type) = content_type {
        proxied
            .headers_mut()
            .insert(header::CONTENT_TYPE, content_type);
    }
    for cookie in set_cookies {
        proxied.headers_mut().append(header::SET_COOKIE, cookie);
    }
    proxied.headers_mut().insert(
        header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    proxied
}

async fn api_account_capabilities_handler() -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        "/v1/capabilities",
        &axum::http::HeaderMap::new(),
        None,
    )
    .await
}

async fn api_account_session_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    proxy_account_request(reqwest::Method::GET, "/v1/sessions", &headers, None).await
}

async fn api_account_resource_get_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        &format!("/v1/accounts/{account_id}"),
        &headers,
        None,
    )
    .await
}

async fn api_account_management_get_handler(
    axum::extract::Path((account_id, resource)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::GET,
        &format!("/v1/accounts/{account_id}/{resource}"),
        &headers,
        None,
    )
    .await
}

async fn api_account_management_post_handler(
    axum::extract::Path((account_id, resource)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/{resource}"),
        &headers,
        Some(body),
    )
    .await
}

async fn api_account_recovery_codes_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/recovery/codes"),
        &headers,
        Some(body),
    )
    .await
}

async fn api_account_membership_revoke_handler(
    axum::extract::Path((account_id, member_account_id)): axum::extract::Path<(String, String)>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/memberships/{member_account_id}/revoke"),
        &headers,
        None,
    )
    .await
}

async fn api_account_invitation_accept_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/invitations/accept",
        &headers,
        Some(body),
    )
    .await
}

async fn api_account_webauthn_options_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/webauthn/authentication/options",
        &headers,
        Some(body),
    )
    .await
}

async fn api_account_webauthn_verify_handler(
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        "/v1/webauthn/authentication/verify",
        &headers,
        Some(body),
    )
    .await
}

async fn api_account_webauthn_registration_options_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/webauthn/registration/options"),
        &headers,
        None,
    )
    .await
}

async fn api_account_webauthn_registration_verify_handler(
    axum::extract::Path(account_id): axum::extract::Path<String>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> axum::response::Response {
    proxy_account_request(
        reqwest::Method::POST,
        &format!("/v1/accounts/{account_id}/webauthn/registration/verify"),
        &headers,
        Some(body),
    )
    .await
}

fn private_ui_router() -> axum::Router {
    use axum::routing::get;

    ui_shell_router()
        .route("/api/context", get(api_private_context_handler))
        .route("/api/account/status", get(api_account_status_handler))
        .route(
            "/api/account/capabilities",
            get(api_account_capabilities_handler),
        )
        .route("/api/account/session", get(api_account_session_handler))
        .route(
            "/api/account/:account_id",
            get(api_account_resource_get_handler),
        )
        .route(
            "/api/account/:account_id/invitations",
            get(api_account_management_get_handler).post(api_account_management_post_handler),
        )
        .route(
            "/api/account/:account_id/memberships",
            get(api_account_management_get_handler),
        )
        .route(
            "/api/account/:account_id/memberships/:member_account_id/revoke",
            axum::routing::post(api_account_membership_revoke_handler),
        )
        .route(
            "/api/account/:account_id/recovery/codes",
            axum::routing::post(api_account_recovery_codes_handler),
        )
        .route(
            "/api/account/invitations/accept",
            axum::routing::post(api_account_invitation_accept_handler),
        )
        .route(
            "/api/account/login",
            axum::routing::post(api_account_login_handler),
        )
        .route(
            "/api/account/logout",
            axum::routing::post(api_account_logout_handler),
        )
        .route(
            "/api/account/webauthn/authentication/options",
            axum::routing::post(api_account_webauthn_options_handler),
        )
        .route(
            "/api/account/webauthn/authentication/verify",
            axum::routing::post(api_account_webauthn_verify_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/options",
            axum::routing::post(api_account_webauthn_registration_options_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/verify",
            axum::routing::post(api_account_webauthn_registration_verify_handler),
        )
        .route(
            "/api/session/revoke",
            axum::routing::post(api_private_session_revoke_handler),
        )
        .route("/api/vault", get(api_vault_handler))
        .route("/api/operators", get(api_operators_handler))
        .route(
            "/api/snapshots",
            get(api_snapshots_handler).post(api_create_snapshot_handler),
        )
        .route(
            "/api/snapshots/:id/manifest",
            get(api_snapshot_manifest_handler),
        )
        .route("/api/activity", get(api_activity_handler))
        .route(
            "/api/anchors",
            get(api_anchors_handler).post(api_create_anchor_handler),
        )
        .route("/api/audit", axum::routing::post(api_audit_handler))
        .route("/api/guardians", get(api_guardians_handler))
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
        )
        .route(
            "/api/fastcdc/vault-files",
            get(api_fastcdc_vault_files_handler),
        )
        .route("/api/diff", get(api_diff_handler))
        .route(
            "/api/files/track",
            axum::routing::post(api_files_track_handler),
        )
        .route(
            "/api/files/untrack",
            axum::routing::post(api_files_untrack_handler),
        )
        .route(
            "/api/snapshots/restore",
            axum::routing::post(api_snapshots_restore_handler),
        )
        .route("/api/workspaces", get(api_workspaces_handler))
        .route(
            "/api/workspaces/switch",
            axum::routing::post(api_workspaces_switch_handler),
        )
        .route(
            "/api/workspaces/scan",
            axum::routing::post(api_workspaces_scan_handler),
        )
        .layer(axum::middleware::from_fn(private_ui_request_guard))
}

fn public_ui_router() -> axum::Router {
    use axum::routing::get;

    ui_shell_router()
        .route("/api/context", get(api_public_context_handler))
        .route("/api/account/status", get(api_account_status_handler))
        .route(
            "/api/account/capabilities",
            get(api_account_capabilities_handler),
        )
        .route("/api/account/session", get(api_account_session_handler))
        .route(
            "/api/account/:account_id",
            get(api_account_resource_get_handler),
        )
        .route(
            "/api/account/:account_id/invitations",
            get(api_account_management_get_handler).post(api_account_management_post_handler),
        )
        .route(
            "/api/account/:account_id/memberships",
            get(api_account_management_get_handler),
        )
        .route(
            "/api/account/:account_id/memberships/:member_account_id/revoke",
            axum::routing::post(api_account_membership_revoke_handler),
        )
        .route(
            "/api/account/:account_id/recovery/codes",
            axum::routing::post(api_account_recovery_codes_handler),
        )
        .route(
            "/api/account/invitations/accept",
            axum::routing::post(api_account_invitation_accept_handler),
        )
        .route(
            "/api/account/logout",
            axum::routing::post(api_account_logout_handler),
        )
        .route(
            "/api/account/webauthn/authentication/options",
            axum::routing::post(api_account_webauthn_options_handler),
        )
        .route(
            "/api/account/webauthn/authentication/verify",
            axum::routing::post(api_account_webauthn_verify_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/options",
            axum::routing::post(api_account_webauthn_registration_options_handler),
        )
        .route(
            "/api/account/:account_id/webauthn/registration/verify",
            axum::routing::post(api_account_webauthn_registration_verify_handler),
        )
        .route("/api/vault", get(api_public_vault_handler))
        .route("/api/operators", get(api_public_operators_handler))
        .route(
            "/api/operators/history",
            get(api_public_operators_history_handler),
        )
        .route(
            "/api/operators/jobs",
            get(api_public_operators_jobs_handler),
        )
        .route("/api/anchors", get(api_public_anchors_handler))
        .route(
            "/api/relayer/checkpoints",
            get(api_public_relayer_checkpoints_handler),
        )
        .route("/api/fleet", get(api_public_fleet_handler))
        .route("/api/stream", get(api_public_stream_handler))
        .fallback(api_public_fallback_handler)
}

fn ui_router(mode: UiServerMode) -> axum::Router {
    match mode {
        UiServerMode::LocalPrivate => private_ui_router(),
        UiServerMode::PublicExplorer => public_ui_router(),
    }
}

fn parse_ui_host(host: &str) -> Result<std::net::IpAddr> {
    if host.eq_ignore_ascii_case("localhost") {
        return Ok(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST));
    }

    host.parse::<std::net::IpAddr>().with_context(|| {
        format!(
            "Invalid UI bind address '{}'. Use a literal IP address or localhost.",
            host
        )
    })
}

fn ui_browser_url(host: std::net::IpAddr, port: u16) -> String {
    let browser_host = if host.is_unspecified() {
        if host.is_ipv4() {
            "127.0.0.1".to_string()
        } else {
            "[::1]".to_string()
        }
    } else if host.is_ipv6() {
        format!("[{}]", host)
    } else {
        host.to_string()
    };
    format!("http://{}:{}", browser_host, port)
}

fn open_browser(url: &str) {
    #[cfg(target_os = "windows")]
    {
        let _ = std::process::Command::new("powershell")
            .args(["-Command", &format!("Start-Process '{}'", url)])
            .spawn();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("open").arg(url).spawn();
    }
    #[cfg(all(not(target_os = "windows"), not(target_os = "macos")))]
    {
        let _ = std::process::Command::new("xdg-open").arg(url).spawn();
    }
}

async fn cmd_ui(
    host: String,
    port: u16,
    no_browser: bool,
    local: bool,
    serve: bool,
    cloud_url: String,
) -> Result<()> {
    if !local && !serve {
        let target_url = cloud_url.trim_end_matches('/').to_string();

        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "{}",
            "  CipherVault Cloud Dashboard & Visual Secrets Explorer"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("  Dashboard URL:  {}", target_url.bold().yellow());
        println!("  Cluster Status: Open the explorer for live operator status");
        println!("  Explorer Scope: Public cluster telemetry and published checkpoints only");
        println!("  Private Vault:  Pass '--local' to open this machine's private workspace.\n");

        if !no_browser {
            println!("Opening {} in default web browser...", target_url.cyan());
            open_browser(&target_url);
        }
        return Ok(());
    }

    let mode = if local {
        UiServerMode::LocalPrivate
    } else {
        UiServerMode::PublicExplorer
    };
    let host_ip = parse_ui_host(&host)?;
    if mode == UiServerMode::LocalPrivate && !host_ip.is_loopback() {
        bail!(
            "Refusing to expose the private local dashboard on {}. Use a loopback address such as 127.0.0.1 or ::1, or use '--serve' for the public read-only explorer.",
            host_ip
        );
    }

    let app = ui_router(mode);
    if mode == UiServerMode::PublicExplorer {
        spawn_public_operator_collector();
    }
    let addr = std::net::SocketAddr::new(host_ip, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let browser_url = ui_browser_url(host_ip, port);

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        match mode {
            UiServerMode::LocalPrivate => {
                "  CipherVault Local Web Dashboard & Vault Inspector"
            }
            UiServerMode::PublicExplorer => "  CipherVault Public Cluster Explorer",
        }
        .bold()
        .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Dashboard URL:  {}", browser_url.bold().yellow());
    match mode {
        UiServerMode::LocalPrivate => {
            println!("  Serving Mode:   Private local workspace (loopback only)");
            println!("  Private APIs:   Enabled for this local process");
        }
        UiServerMode::PublicExplorer => {
            println!("  Serving Mode:   Public read-only explorer");
            println!("  Private APIs:   Disabled (use 'ciphervault ui --local' on the vault host)");
        }
    }
    println!("  Press Ctrl+C to stop server.\n");

    if !no_browser {
        let local_url = browser_url;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            open_browser(&local_url);
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}

async fn api_private_context_handler() -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    let session = private_ui_session_snapshot();
    let mut context = ui_context(UiServerMode::LocalPrivate);
    if let Some(object) = context.as_object_mut() {
        object.insert(
            "session".to_string(),
            serde_json::json!({
                "scheme": "http_only_cookie",
                "vault_bound": session.vault_binding.is_some(),
                "ttl_seconds": PRIVATE_UI_SESSION_TTL.as_secs(),
                "revocation_endpoint": "/api/session/revoke",
            }),
        );
        object.insert("account".to_string(), current_account_context());
    }
    let mut response = axum::Json(context).into_response();
    let cookie = format!(
        "ciphervault_private_session={}; Path=/; Max-Age={}; HttpOnly; SameSite=Strict",
        session.token,
        PRIVATE_UI_SESSION_TTL.as_secs()
    );
    response.headers_mut().insert(
        header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&cookie)
            .expect("generated private session cookie must be valid"),
    );
    response
}

async fn api_account_status_handler() -> axum::Json<serde_json::Value> {
    axum::Json(current_account_context())
}

async fn api_account_login_handler() -> axum::response::Response {
    use axum::response::IntoResponse;

    let account = match AccountStore::open(None) {
        Ok(account) => account,
        Err(error) => {
            return (
                axum::http::StatusCode::NOT_FOUND,
                axum::Json(serde_json::json!({
                    "status": "error",
                    "code": "ACCOUNT_NOT_CONFIGURED",
                    "error": error.to_string(),
                })),
            )
                .into_response();
        }
    };
    let Ok((vault_id, device_id, _)) = current_device_identity() else {
        return (
            axum::http::StatusCode::BAD_REQUEST,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "VAULT_NOT_INITIALIZED",
                "error": "A local vault is required to bind an account session.",
            })),
        )
            .into_response();
    };
    if !account.is_vault_linked(&vault_id) {
        return (
            axum::http::StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "VAULT_NOT_LINKED",
                "error": "Link this vault with `ciphervault vault link` before logging in here.",
            })),
        )
            .into_response();
    }
    match account.login(Some(&device_id)) {
        Ok(status) => axum::Json(serde_json::json!({
            "status": "ok",
            "account": status,
        }))
        .into_response(),
        Err(error) => (
            axum::http::StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_LOGIN_FAILED",
                "error": error.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn api_account_logout_handler(headers: axum::http::HeaderMap) -> axum::response::Response {
    use axum::response::IntoResponse;
    let has_hosted_cookie = headers
        .get(axum::http::header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|cookies| {
            cookies
                .split(';')
                .any(|cookie| cookie.trim().starts_with("ciphervault_account_session="))
        });
    if hosted_account_endpoint().is_some() && has_hosted_cookie {
        return proxy_account_request(reqwest::Method::POST, "/v1/sessions/revoke", &headers, None)
            .await;
    }
    match AccountStore::open(None).and_then(|account| account.logout()) {
        Ok(()) => {
            revoke_private_ui_session();
            axum::Json(serde_json::json!({ "status": "ok", "authenticated": false }))
                .into_response()
        }
        Err(error) => (
            axum::http::StatusCode::NOT_FOUND,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "ACCOUNT_NOT_CONFIGURED",
                "error": error.to_string(),
            })),
        )
            .into_response(),
    }
}

async fn api_private_session_revoke_handler() -> axum::response::Response {
    use axum::{http::header, response::IntoResponse};

    revoke_private_ui_session();
    let mut response = axum::Json(serde_json::json!({
        "status": "ok",
        "revoked": true,
        "message": "The current private dashboard session was revoked. Open /api/context to establish a new session.",
    }))
    .into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "ciphervault_private_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict",
        ),
    );
    response
}

async fn api_public_context_handler() -> axum::Json<serde_json::Value> {
    axum::Json(ui_context(UiServerMode::PublicExplorer))
}

async fn api_public_vault_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "mode": UiServerMode::PublicExplorer.name(),
        "access_mode": UiServerMode::PublicExplorer.access_mode(),
        "capabilities": ui_capabilities(UiServerMode::PublicExplorer),
        "service": "CipherVault public cluster explorer",
        "private_vault_access": false,
        "message": "This public explorer does not expose vault identity, files, snapshots, recovery descriptors, or private actions.",
    }))
}

async fn api_public_fallback_handler(uri: axum::http::Uri) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    if uri.path().starts_with("/api/") {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "PRIVATE_API_DISABLED",
                "error": "This API is available only from a loopback-bound local private workspace.",
            })),
        )
            .into_response();
    }

    StatusCode::NOT_FOUND.into_response()
}

fn local_host_name(value: &str) -> Option<String> {
    if value.eq_ignore_ascii_case("localhost") {
        return Some("localhost".to_string());
    }
    let address = value.parse::<std::net::IpAddr>().ok()?;
    if address.is_loopback() {
        Some(address.to_string().to_ascii_lowercase())
    } else {
        None
    }
}

fn local_authority(value: &str) -> Option<(String, u16)> {
    let authority = value.trim();
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let end = rest.find(']')?;
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|raw| raw.parse::<u16>().ok())
            .unwrap_or(80);
        (host, port)
    } else if let Some((host, raw_port)) = authority.rsplit_once(':') {
        if let Ok(port) = raw_port.parse::<u16>() {
            (host, port)
        } else {
            (authority, 80)
        }
    } else {
        (authority, 80)
    };
    Some((local_host_name(host)?, port))
}

async fn private_ui_request_guard(
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    let headers = request.headers();
    let host = headers
        .get(axum::http::header::HOST)
        .and_then(|value| value.to_str().ok())
        .and_then(local_authority);
    let origin = headers
        .get(axum::http::header::ORIGIN)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| {
            let url = reqwest::Url::parse(value).ok()?;
            if url.scheme() != "http" || url.username() != "" || url.password().is_some() {
                return None;
            }
            let host = local_host_name(url.host_str()?)?;
            Some((host, url.port_or_known_default().unwrap_or(80)))
        });
    let origin_header_present = headers.contains_key(axum::http::header::ORIGIN);
    let is_mutation = matches!(
        request.method(),
        &axum::http::Method::POST
            | &axum::http::Method::PUT
            | &axum::http::Method::PATCH
            | &axum::http::Method::DELETE
    );
    let origin_matches_host = origin
        .as_ref()
        .zip(host.as_ref())
        .is_some_and(|(origin, host)| origin == host);

    let path = request.uri().path();
    let is_api = path.starts_with("/api/");
    let is_context = path == "/api/context";
    let is_account_bootstrap = matches!(
        path,
        "/api/account/status"
            | "/api/account/login"
            | "/api/account/logout"
            | "/api/account/capabilities"
            | "/api/account/session"
            | "/api/account/webauthn/authentication/options"
            | "/api/account/webauthn/authentication/verify"
    ) || (path.starts_with("/api/account/")
        && path.ends_with("/webauthn/registration/options"))
        || (path.starts_with("/api/account/") && path.ends_with("/webauthn/registration/verify"));
    let session_valid = if is_api && !is_context && !is_account_bootstrap {
        let session = private_ui_session_snapshot();
        let private_cookie_valid = headers
            .get(axum::http::header::COOKIE)
            .and_then(|value| value.to_str().ok())
            .and_then(|cookies| {
                cookies.split(';').find_map(|cookie| {
                    let (name, value) = cookie.trim().split_once('=')?;
                    (name == "ciphervault_private_session").then_some(value)
                })
            })
            .is_some_and(|value| value == session.token);
        private_cookie_valid && private_account_session_valid()
    } else {
        true
    };

    if host.is_none()
        || (origin_header_present && (origin.is_none() || !origin_matches_host))
        || (is_mutation && (origin.is_none() || !origin_matches_host))
    {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "LOCAL_ORIGIN_REQUIRED",
                "error": "Private dashboard requests must originate from the loopback dashboard address.",
            })),
        )
            .into_response();
    }

    if is_api && !is_context && !session_valid {
        return (
            StatusCode::UNAUTHORIZED,
            axum::Json(serde_json::json!({
                "status": "error",
                "code": "PRIVATE_SESSION_REQUIRED",
                "error": "Open the loopback private dashboard context before calling private APIs.",
            })),
        )
            .into_response();
    }

    let mut response = next.run(request).await;
    let response_headers = response.headers_mut();
    response_headers.insert(
        axum::http::header::CACHE_CONTROL,
        axum::http::HeaderValue::from_static("no-store"),
    );
    response_headers.insert(
        axum::http::header::X_CONTENT_TYPE_OPTIONS,
        axum::http::HeaderValue::from_static("nosniff"),
    );
    response_headers.insert(
        axum::http::header::X_FRAME_OPTIONS,
        axum::http::HeaderValue::from_static("DENY"),
    );
    response
}

fn public_operator_id(operator_id: &str, index: usize) -> String {
    let safe_id = operator_id
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .collect::<String>();
    if safe_id.is_empty() {
        format!("operator-{}", index + 1)
    } else {
        safe_id
    }
}

/// Returns true only when an operator identity is present in the independently
/// configured trust registry.  A self-signed `/v1/info` response proves that
/// the responder controls the returned key, but it does not prove that the key
/// is the key the deployment intended to contact.
///
/// `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES` accepts comma-separated entries in
/// either `operator-id=64-byte-hex-key` form or as a bare public key.  The
/// registry is deliberately opt-in: when it is absent, public telemetry stays
/// unverified instead of silently falling back to trust-on-first-use.
fn trusted_public_operator_identity_from_registry(
    registry: &str,
    operator_id: &str,
    public_key_hex: &str,
) -> bool {
    let key = public_key_hex
        .trim()
        .trim_start_matches("0x")
        .to_ascii_lowercase();
    if key.len() != 64 || !key.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }

    registry.split(',').any(|entry| {
        let entry = entry.trim();
        if entry.is_empty() {
            return false;
        }
        let (entry_id, entry_key) = entry
            .split_once('=')
            .map_or((None, entry), |(id, key)| (Some(id.trim()), key.trim()));
        let entry_key = entry_key.trim_start_matches("0x").to_ascii_lowercase();
        entry_key == key
            && entry_id.is_none_or(|id| !id.is_empty() && id.eq_ignore_ascii_case(operator_id))
    })
}

fn trusted_public_operator_identity(operator_id: &str, public_key_hex: &str) -> bool {
    std::env::var("CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES")
        .ok()
        .is_some_and(|registry| {
            trusted_public_operator_identity_from_registry(&registry, operator_id, public_key_hex)
        })
}

const PUBLIC_OPERATOR_PROBE_TIMEOUT: Duration = Duration::from_secs(3);
const PUBLIC_OPERATOR_CACHE_TTL: Duration = Duration::from_secs(30);
const PUBLIC_OPERATOR_PERSISTED_MAX_AGE: Duration = Duration::from_secs(90);

#[derive(Clone)]
struct PublicOperatorTelemetry {
    observed_at: chrono::DateTime<Utc>,
    cached_at: Instant,
    operators: Vec<serde_json::Value>,
}

static PUBLIC_OPERATOR_TELEMETRY_CACHE: OnceLock<
    tokio::sync::Mutex<Option<PublicOperatorTelemetry>>,
> = OnceLock::new();
static PUBLIC_OPERATOR_HTTP_CLIENT: OnceLock<HttpClient> = OnceLock::new();

fn public_operator_http_client() -> HttpClient {
    PUBLIC_OPERATOR_HTTP_CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .connect_timeout(Duration::from_secs(2))
                .timeout(PUBLIC_OPERATOR_PROBE_TIMEOUT)
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(2)
                .tcp_keepalive(Some(Duration::from_secs(30)))
                .build()
                .unwrap_or_else(|_| HttpClient::new())
        })
        .clone()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedPublicOperatorTelemetry {
    observed_at_utc: String,
    operators: Vec<serde_json::Value>,
}

fn public_operator_telemetry_path() -> Option<PathBuf> {
    std::env::var("CIPHERVAULT_PUBLIC_OPERATOR_TELEMETRY_FILE")
        .ok()
        .filter(|path| !path.trim().is_empty())
        .map(PathBuf::from)
}

const PUBLIC_OPERATOR_HISTORY_MAX: usize = 288;
const PUBLIC_OPERATOR_JOB_HISTORY_MAX: usize = 1_000;

fn public_operator_history_path() -> Option<PathBuf> {
    let path = public_operator_telemetry_path()?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operator-telemetry.json");
    Some(path.with_file_name(format!("{}.history.jsonl", name)))
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedPublicOperatorHistoryEntry {
    observed_at_utc: String,
    operators: Vec<serde_json::Value>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PersistedPublicOperatorJob {
    job_id: String,
    started_at_utc: String,
    completed_at_utc: String,
    status: String,
    #[serde(default)]
    regions: Vec<String>,
    operator_count: usize,
    reachable_count: usize,
    failure_count: usize,
    #[serde(default)]
    attempts: usize,
    #[serde(default)]
    retry_count: usize,
    #[serde(default)]
    error_summary: Option<String>,
}

fn public_operator_jobs_path() -> Option<PathBuf> {
    let path = public_operator_telemetry_path()?;
    let name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("operator-telemetry.json");
    Some(path.with_file_name(format!("{}.jobs.jsonl", name)))
}

fn load_persisted_public_operator_telemetry() -> Option<PublicOperatorTelemetry> {
    let path = public_operator_telemetry_path()?;
    let contents = fs::read_to_string(path).ok()?;
    let persisted: PersistedPublicOperatorTelemetry = serde_json::from_str(&contents).ok()?;
    let observed_at = chrono::DateTime::parse_from_rfc3339(&persisted.observed_at_utc)
        .ok()?
        .with_timezone(&Utc);
    let now = Utc::now();
    if observed_at > now + chrono::Duration::minutes(5)
        || now.signed_duration_since(observed_at).to_std().ok()? > PUBLIC_OPERATOR_PERSISTED_MAX_AGE
    {
        return None;
    }
    Some(PublicOperatorTelemetry {
        observed_at,
        cached_at: Instant::now(),
        operators: persisted.operators,
    })
}

fn persist_public_operator_telemetry(snapshot: &PublicOperatorTelemetry) -> Result<()> {
    let path = public_operator_telemetry_path()
        .context("public operator telemetry persistence path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let payload = serde_json::to_vec_pretty(&PersistedPublicOperatorTelemetry {
        observed_at_utc: snapshot.observed_at.to_rfc3339(),
        operators: snapshot.operators.clone(),
    })?;
    let temp_path = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("operator-telemetry.json"),
        std::process::id()
    ));
    fs::write(&temp_path, payload)?;
    let result = (|| -> Result<()> {
        if path.exists() {
            fs::remove_file(&path)?;
        }
        fs::rename(&temp_path, &path)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temp_path);
    }
    result
}

fn persist_public_operator_history(snapshot: &PublicOperatorTelemetry) -> Result<()> {
    let path = public_operator_history_path()
        .context("public operator telemetry history path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut entries = fs::read_to_string(&path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    serde_json::from_str::<PersistedPublicOperatorHistoryEntry>(line).ok()
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    entries.push(PersistedPublicOperatorHistoryEntry {
        observed_at_utc: snapshot.observed_at.to_rfc3339(),
        operators: snapshot.operators.clone(),
    });
    if entries.len() > PUBLIC_OPERATOR_HISTORY_MAX {
        entries.drain(..entries.len() - PUBLIC_OPERATOR_HISTORY_MAX);
    }
    let encoded = entries
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("operator-history.jsonl"),
        std::process::id()
    ));
    fs::write(&tmp, format!("{}\n", encoded))?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn persist_public_operator_job(job: &PersistedPublicOperatorJob) -> Result<()> {
    let path = public_operator_jobs_path()
        .context("public operator job persistence path is not configured")?;
    if let Some(parent) = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
    {
        fs::create_dir_all(parent)?;
    }
    let mut jobs = fs::read_to_string(&path)
        .ok()
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| serde_json::from_str::<PersistedPublicOperatorJob>(line).ok())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    jobs.push(PersistedPublicOperatorJob {
        job_id: job.job_id.clone(),
        started_at_utc: job.started_at_utc.clone(),
        completed_at_utc: job.completed_at_utc.clone(),
        status: job.status.clone(),
        regions: job.regions.clone(),
        operator_count: job.operator_count,
        reachable_count: job.reachable_count,
        failure_count: job.failure_count,
        attempts: job.attempts,
        retry_count: job.retry_count,
        error_summary: job.error_summary.clone(),
    });
    if jobs.len() > PUBLIC_OPERATOR_JOB_HISTORY_MAX {
        jobs.drain(..jobs.len() - PUBLIC_OPERATOR_JOB_HISTORY_MAX);
    }
    let encoded = jobs
        .iter()
        .map(serde_json::to_string)
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    let tmp = path.with_file_name(format!(
        ".{}.tmp-{}",
        path.file_name()
            .and_then(|value| value.to_str())
            .unwrap_or("operator-jobs.jsonl"),
        std::process::id()
    ));
    fs::write(&tmp, format!("{}\n", encoded))?;
    if path.exists() {
        fs::remove_file(&path)?;
    }
    fs::rename(tmp, path)?;
    Ok(())
}

fn load_public_operator_jobs() -> Vec<serde_json::Value> {
    public_operator_jobs_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| serde_json::from_str::<PersistedPublicOperatorJob>(line).ok())
                .map(|job| serde_json::to_value(job).unwrap_or(serde_json::Value::Null))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default()
}

fn spawn_public_operator_collector() {
    if public_operator_telemetry_path().is_none() {
        return;
    }
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(PUBLIC_OPERATOR_CACHE_TTL);
        loop {
            interval.tick().await;
            let started_at = Utc::now();
            let snapshot = PublicOperatorTelemetry {
                observed_at: started_at,
                cached_at: Instant::now(),
                operators: probe_public_operators_uncached().await,
            };
            let operator_count = snapshot.operators.len();
            let reachable_count = snapshot
                .operators
                .iter()
                .filter(|operator| operator["status"] == "reachable")
                .count();
            let failure_count = operator_count.saturating_sub(reachable_count);
            let attempts = snapshot
                .operators
                .iter()
                .filter_map(|operator| {
                    operator
                        .get("probe_attempts")
                        .and_then(serde_json::Value::as_u64)
                })
                .map(|value| value as usize)
                .sum::<usize>();
            let retry_count = attempts.saturating_sub(operator_count);
            let status = if operator_count == 0 || reachable_count == 0 {
                "failed"
            } else if failure_count > 0 {
                "degraded"
            } else {
                "succeeded"
            };
            if let Err(error) = persist_public_operator_telemetry(&snapshot) {
                eprintln!("Public operator telemetry persistence failed: {error}");
            }
            if let Err(error) = persist_public_operator_history(&snapshot) {
                eprintln!("Public operator telemetry history persistence failed: {error}");
            }
            if let Err(error) = persist_public_operator_job(&PersistedPublicOperatorJob {
                job_id: hex::encode(rand::random::<[u8; 16]>()),
                started_at_utc: started_at.to_rfc3339(),
                completed_at_utc: Utc::now().to_rfc3339(),
                status: status.to_string(),
                regions: {
                    let mut regions = snapshot
                        .operators
                        .iter()
                        .filter_map(|operator| operator.get("region"))
                        .filter_map(serde_json::Value::as_str)
                        .map(str::to_string)
                        .collect::<Vec<_>>();
                    regions.sort();
                    regions.dedup();
                    regions
                },
                operator_count,
                reachable_count,
                failure_count,
                attempts,
                retry_count,
                error_summary: (failure_count > 0)
                    .then(|| format!("{failure_count} operator probe(s) failed")),
            }) {
                eprintln!("Public operator collector job persistence failed: {error}");
            }
        }
    });
}

async fn probe_public_operators_uncached() -> Vec<serde_json::Value> {
    const MAX_ATTEMPTS: usize = 3;
    let http = public_operator_http_client();
    let probes =
        get_configured_operator_regions()
            .into_iter()
            .enumerate()
            .map(|(index, (endpoint, region))| {
                let http = http.clone();
                async move {
                let client = OperatorClient::with_http_client(endpoint, http.clone());
                let start = std::time::Instant::now();
                let mut attempts = 0usize;
                let result = loop {
                    attempts += 1;
                    match tokio::time::timeout(PUBLIC_OPERATOR_PROBE_TIMEOUT, client.get_info()).await {
                        Ok(Ok(info)) => break Ok(info),
                        Ok(Err(error)) if attempts < MAX_ATTEMPTS => {
                            tokio::time::sleep(Duration::from_millis(75 * attempts as u64)).await;
                            let _ = error;
                        }
                        Err(_) if attempts < MAX_ATTEMPTS => {
                            tokio::time::sleep(Duration::from_millis(75 * attempts as u64)).await;
                        }
                        Ok(Err(error)) => break Err(error.to_string()),
                        Err(_) => break Err("probe timeout".to_string()),
                    }
                };
                match result {
                    Ok(info) => {
                        let self_signed = info.verify_identity_signature();
                        let identity_pinned = self_signed
                            && trusted_public_operator_identity(
                                &info.operator_id,
                                &info.operator_signing_pk_hex,
                            );
                        serde_json::json!({
                        "display_name": format!("Operator {}", index + 1),
                        "operator_id": public_operator_id(&info.operator_id, index),
                        "region": region,
                        "status": "reachable",
                        "identity_verification": if identity_pinned { "verified" } else { "unverified" },
                        "identity_self_signature": if self_signed { "valid" } else { "invalid" },
                        "identity_trust": if identity_pinned { "pinned" } else { "not_pinned" },
                        "identity_expires_at_utc": info.identity_expires_at_utc,
                        "identity_signature_present": !info.identity_signature_hex.is_empty(),
                        "latency_ms": start.elapsed().as_millis(),
                        "probe_attempts": attempts,
                        })
                    }
                    Err(error) => serde_json::json!({
                        "display_name": format!("Operator {}", index + 1),
                        "operator_id": format!("operator-{}", index + 1),
                        "region": region,
                        "status": "unreachable",
                        "identity_verification": "not_observed",
                        "identity_self_signature": "not_observed",
                        "identity_trust": "not_observed",
                        "identity_signature_present": false,
                        "latency_ms": serde_json::Value::Null,
                        "probe_attempts": attempts,
                        "error": error,
                    }),
                }
                }
            });

    join_all(probes).await
}

async fn public_operator_telemetry() -> PublicOperatorTelemetry {
    if let Some(snapshot) = load_persisted_public_operator_telemetry() {
        let cache = PUBLIC_OPERATOR_TELEMETRY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
        *cache.lock().await = Some(snapshot.clone());
        return snapshot;
    }
    let cache = PUBLIC_OPERATOR_TELEMETRY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let mut cached = cache.lock().await;
    if let Some(snapshot) = cached.as_ref() {
        if snapshot.cached_at.elapsed() < PUBLIC_OPERATOR_CACHE_TTL {
            return snapshot.clone();
        }
    }

    // Hold this lock while probing so a burst of browser requests has one
    // shared measurement instead of fanning out requests to every operator.
    let snapshot = PublicOperatorTelemetry {
        observed_at: Utc::now(),
        cached_at: Instant::now(),
        operators: probe_public_operators_uncached().await,
    };
    *cached = Some(snapshot.clone());
    snapshot
}

async fn api_public_operators_handler() -> axum::Json<serde_json::Value> {
    let telemetry = public_operator_telemetry().await;
    let observed_at = telemetry.observed_at.to_rfc3339();
    let operators = telemetry
        .operators
        .into_iter()
        .map(|mut operator| {
            if let Some(object) = operator.as_object_mut() {
                object.insert(
                    "observed_at".to_string(),
                    serde_json::Value::String(observed_at.clone()),
                );
            }
            operator
        })
        .collect::<Vec<_>>();
    axum::Json(serde_json::json!(operators))
}

async fn api_public_operators_history_handler() -> axum::Json<serde_json::Value> {
    let samples = public_operator_history_path()
        .and_then(|path| fs::read_to_string(path).ok())
        .map(|contents| {
            contents
                .lines()
                .filter_map(|line| {
                    serde_json::from_str::<PersistedPublicOperatorHistoryEntry>(line).ok()
                })
                .map(|entry| {
                    serde_json::json!({
                        "observed_at": entry.observed_at_utc,
                        "operators": entry.operators,
                    })
                })
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    axum::Json(serde_json::json!({
        "samples": samples,
        "sample_limit": PUBLIC_OPERATOR_HISTORY_MAX,
    }))
}

async fn api_public_operators_jobs_handler() -> axum::Json<serde_json::Value> {
    axum::Json(serde_json::json!({
        "jobs": load_public_operator_jobs(),
        "job_limit": PUBLIC_OPERATOR_JOB_HISTORY_MAX,
        "message": "Collector job history is observational telemetry; it does not establish storage durability or quorum.",
    }))
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PublicCheckpointFeedEntry {
    network: String,
    chain_id: u64,
    contract_address_hex: String,
    commitment_hex: String,
    head_record_cid_hex: String,
    #[serde(default)]
    tx_hash_hex: Option<String>,
    #[serde(default)]
    block_number: Option<u64>,
    published_at_utc: u64,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PublicCheckpointFeedUnsigned {
    version: u32,
    issued_at_utc: u64,
    checkpoints: Vec<PublicCheckpointFeedEntry>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct PublicCheckpointFeedEnvelope {
    version: u32,
    issued_at_utc: u64,
    checkpoints: Vec<PublicCheckpointFeedEntry>,
    publisher_key_hex: String,
    signature_hex: String,
}

fn verify_public_checkpoint_feed(
    feed: &PublicCheckpointFeedEnvelope,
) -> Result<Vec<serde_json::Value>, String> {
    const MAX_PUBLIC_CHECKPOINTS: usize = 1_000;
    const MAX_PUBLIC_FEED_AGE_SECS: u64 = 7 * 24 * 60 * 60;
    const MAX_PUBLIC_FEED_FUTURE_SKEW_SECS: u64 = 5 * 60;
    if feed.version != 1 {
        return Err("Unsupported public checkpoint feed version".to_string());
    }
    if feed.checkpoints.len() > MAX_PUBLIC_CHECKPOINTS {
        return Err("Public checkpoint feed exceeds the 1,000 record limit".to_string());
    }
    let now = Utc::now().timestamp().max(0) as u64;
    if feed.issued_at_utc > now.saturating_add(MAX_PUBLIC_FEED_FUTURE_SKEW_SECS) {
        return Err("Public checkpoint feed timestamp is too far in the future".to_string());
    }
    if now.saturating_sub(feed.issued_at_utc) > MAX_PUBLIC_FEED_AGE_SECS {
        return Err("Public checkpoint feed is stale".to_string());
    }

    let publisher_key = hex::decode(feed.publisher_key_hex.trim_start_matches("0x"))
        .map_err(|_| "Public checkpoint publisher key is not valid hex".to_string())?;
    if publisher_key.len() != 32 {
        return Err("Public checkpoint publisher key must be 32 bytes".to_string());
    }
    let mut publisher_key_arr = [0u8; 32];
    publisher_key_arr.copy_from_slice(&publisher_key);

    let signature = hex::decode(feed.signature_hex.trim_start_matches("0x"))
        .map_err(|_| "Public checkpoint feed signature is not valid hex".to_string())?;
    if signature.len() != 64 {
        return Err("Public checkpoint feed signature must be 64 bytes".to_string());
    }
    let mut signature_arr = [0u8; 64];
    signature_arr.copy_from_slice(&signature);

    let unsigned = PublicCheckpointFeedUnsigned {
        version: feed.version,
        issued_at_utc: feed.issued_at_utc,
        checkpoints: feed.checkpoints.clone(),
    };
    let message = ciphervault_format::to_canonical_cbor(&unsigned)
        .map_err(|e| format!("Unable to canonicalize public checkpoint feed: {e}"))?;
    ciphervault_crypto::signatures::verify_with_domain(
        &publisher_key_arr,
        b"public_checkpoint_feed",
        &message,
        &signature_arr,
    )
    .map_err(|_| "Public checkpoint feed signature verification failed".to_string())?;

    feed.checkpoints
        .iter()
        .map(|checkpoint| {
            if checkpoint.network.trim().is_empty() || checkpoint.chain_id == 0 {
                return Err("Public checkpoint feed contains an incomplete network record".to_string());
            }
            for (label, value, expected_len) in [
                ("contract address", checkpoint.contract_address_hex.as_str(), 40usize),
                ("commitment", checkpoint.commitment_hex.as_str(), 64usize),
                ("head record CID", checkpoint.head_record_cid_hex.as_str(), 64usize),
            ] {
                let decoded = hex::decode(value.trim_start_matches("0x"))
                    .map_err(|_| format!("Public checkpoint {label} is not valid hex"))?;
                if decoded.len() != expected_len / 2 {
                    return Err(format!("Public checkpoint {label} has an invalid length"));
                }
            }
            if let Some(tx_hash) = checkpoint.tx_hash_hex.as_deref() {
                let decoded = hex::decode(tx_hash.trim_start_matches("0x"))
                    .map_err(|_| "Public checkpoint transaction hash is not valid hex".to_string())?;
                if decoded.len() != 32 {
                    return Err("Public checkpoint transaction hash has an invalid length".to_string());
                }
            }

            let tx_hash = checkpoint.tx_hash_hex.clone().unwrap_or_default();
            let has_transaction = !tx_hash.is_empty();
            Ok(serde_json::json!({
                "network": &checkpoint.network,
                "chain_id": checkpoint.chain_id,
                "contract_address_hex": &checkpoint.contract_address_hex,
                "commitment_hex": &checkpoint.commitment_hex,
                "head_record_cid_hex": &checkpoint.head_record_cid_hex,
                "tx_hash_hex": if has_transaction { serde_json::Value::String(tx_hash) } else { serde_json::Value::Null },
                "reported_block_number": checkpoint.block_number,
                "published_at_utc": checkpoint.published_at_utc,
                "status": if has_transaction { "Published" } else { "QueuedForRelay" },
                "verification_status": "publisher_signed",
                "finality_status": "unverified",
                "publisher_key_hex": &feed.publisher_key_hex,
            }))
        })
        .collect()
}

fn load_public_checkpoint_feed() -> Result<Option<Vec<serde_json::Value>>, String> {
    let path = match std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_FEED") {
        Ok(path) if !path.trim().is_empty() => PathBuf::from(path),
        _ => return Ok(None),
    };
    let contents = fs::read_to_string(&path)
        .map_err(|_| "Configured public checkpoint feed could not be read".to_string())?;
    let feed: PublicCheckpointFeedEnvelope = serde_json::from_str(&contents)
        .map_err(|_| "Configured public checkpoint feed is not valid JSON".to_string())?;
    verify_public_checkpoint_feed(&feed).map(Some)
}

async fn api_public_anchors_handler() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    match load_public_checkpoint_feed() {
        Ok(Some(checkpoints)) => axum::Json(checkpoints).into_response(),
        Ok(None) => axum::Json(serde_json::json!([])).into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "error",
                "verification_status": "invalid",
                "error": error,
            })),
        )
            .into_response(),
    }
}

async fn api_public_relayer_checkpoints_handler() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    match load_public_checkpoint_feed() {
        Ok(Some(checkpoints)) => {
            let checkpoint_count = checkpoints.len();
            let network = checkpoints
                .first()
                .and_then(|checkpoint| checkpoint.get("network"))
                .and_then(|network| network.as_str())
                .unwrap_or("Published checkpoint feed");
            axum::Json(serde_json::json!({
                "status": "ok",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": network,
                    "verification_status": "publisher_signed",
                    "finality_status": "unverified",
                },
                "checkpoints": checkpoints,
                "count": checkpoint_count,
                "message": "Checkpoint records are signed by the configured publisher; chain receipt and finality remain independently unverified.",
            }))
            .into_response()
        }
        Ok(None) => axum::Json(serde_json::json!({
            "status": "ok",
            "access_mode": "public",
            "relayer_status": {
                "public_read_only": true,
                "target_network": "No public checkpoint feed configured",
                "verification_status": "unavailable",
            },
            "checkpoints": [],
            "count": 0,
            "message": "A signed public checkpoint feed has not been configured. Private vault checkpoint evidence remains available only in a loopback workspace.",
        }))
        .into_response(),
        Err(error) => (
            StatusCode::SERVICE_UNAVAILABLE,
            axum::Json(serde_json::json!({
                "status": "error",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": "Public checkpoint feed unavailable",
                    "verification_status": "invalid",
                },
                "checkpoints": [],
                "count": 0,
                "error": error,
            })),
        )
            .into_response(),
    }
}

async fn api_public_fleet_handler() -> axum::Json<serde_json::Value> {
    let operator_count = get_configured_operators().len();
    axum::Json(serde_json::json!({
        "status": "ok",
        "access_mode": "public",
        "fleet_summary": {
            "total_operators": operator_count,
        },
        "operator_nodes": [],
        "vaults": [],
        "audit_history": [],
        "message": "Vault fleet inventory and audit history are available only in a private local workspace.",
    }))
}

async fn api_public_stream_handler(
) -> Sse<impl Stream<Item = Result<Event, std::convert::Infallible>>> {
    let stream = stream::unfold((), |_| async {
        let telemetry = public_operator_telemetry().await;
        let observed_at = telemetry.observed_at;
        let operators = telemetry
            .operators
            .into_iter()
            .map(|operator| {
                let reachable = operator["status"] == "reachable";
                serde_json::json!({
                    "operator": operator["operator_id"],
                    "online": reachable,
                    "identity_verification": operator["identity_verification"],
                    "latency_ms": operator["latency_ms"],
                })
            })
            .collect::<Vec<_>>();

        let event = Event::default().event("telemetry").data(
            serde_json::json!({
                "timestamp": observed_at.to_rfc3339(),
                "operators": operators,
            })
            .to_string(),
        );
        tokio::time::sleep(PUBLIC_OPERATOR_CACHE_TTL).await;
        Some((Ok(event), ()))
    });

    Sse::new(stream).keep_alive(KeepAlive::default())
}

async fn api_vault_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "initialized": false,
                "message": "No vault initialized in current directory",
                "mode": UiServerMode::LocalPrivate.name(),
                "access_mode": UiServerMode::LocalPrivate.access_mode(),
                "capabilities": ui_capabilities(UiServerMode::LocalPrivate),
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
        "mode": UiServerMode::LocalPrivate.name(),
        "access_mode": UiServerMode::LocalPrivate.access_mode(),
        "capabilities": ui_capabilities(UiServerMode::LocalPrivate),
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
        "operators": operators.iter().map(|op| mask_operator_endpoint(op)).collect::<Vec<_>>(),
        "recovery": recovery_info,
    }))
}

async fn api_operators_handler() -> impl axum::response::IntoResponse {
    let http = public_operator_http_client();
    let probes = get_configured_operators().into_iter().map(|endpoint| {
        let http = http.clone();
        async move {
        let client = OperatorClient::with_http_client(endpoint.clone(), http);
        let start = std::time::Instant::now();
        let transport_security = if endpoint
            .trim_start()
            .to_ascii_lowercase()
            .starts_with("https://")
        {
            "https"
        } else {
            "http_or_unknown"
        };
        match client.get_info().await {
            Ok(info) => {
                let latency_ms = start.elapsed().as_millis();
                let identity_verified = info.verify_identity_signature();
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
                let display_endpoint = mask_operator_endpoint(&endpoint);
                serde_json::json!({
                    "endpoint": display_endpoint,
                    "target_url": display_endpoint,
                    "status": "online",
                    "operator_id": if safe_id.is_empty() { "operator" } else { &safe_id },
                    "operator_signing_pk_hex": safe_pk,
                    "latency_ms": latency_ms,
                    "retention_terms": info.retention_terms,
                    "transport_security": transport_security,
                    "identity_verification": if identity_verified { "verified" } else { "unverified" },
                    "identity_expires_at_utc": info.identity_expires_at_utc,
                    "identity_signature_present": !info.identity_signature_hex.is_empty(),
                })
            }
            Err(_) => {
                let display_endpoint = mask_operator_endpoint(&endpoint);
                serde_json::json!({
                    "endpoint": display_endpoint,
                    "target_url": display_endpoint,
                    "status": "offline",
                    "error": "Operator did not respond",
                    "transport_security": transport_security,
                    "identity_verification": "not_observed",
                })
            }
        }
        }
    });
    let results = join_all(probes).await;

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
    anchor: Option<bool>,
}

async fn api_create_snapshot_handler(
    axum::Json(payload): axum::Json<CreateSnapshotRequest>,
) -> impl axum::response::IntoResponse {
    match cmd_push(
        payload.message,
        false,
        false,
        payload.anchor.unwrap_or(false),
        None,
        None,
    )
    .await
    {
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
                "status": "ok",
                "success": true,
                "snapshot_id_hex": snap_id,
                "message": "Snapshot successfully captured, encrypted, and replicated across operators"
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_create_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None, None, false, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": "Snapshot head commitment successfully prepared and recorded for Arbitrum One"
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
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
        "message": "No guardian ceremony status is stored in the dashboard. Use the local CLI and approved offline procedure for guardian recovery material.",
    }))
}

async fn api_relayer_checkpoints_handler() -> impl axum::response::IntoResponse {
    let store_res = get_vault_store();
    let store = match store_res {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "status": "ok",
                "relayer_status": {
                    "operational": null,
                    "status": "not_configured",
                    "target_network": null,
                    "verification_status": "unavailable"
                },
                "checkpoints": [],
                "count": 0
            }))
        }
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
            } else if ev.chain_id == 421614 {
                format!("https://sepolia.arbiscan.io/tx/{}", tx_hex)
            } else {
                String::new()
            };

            let status_str = if is_empty_tx { "not_submitted" } else { "submitted" };
            let verification_status = if is_empty_tx {
                "not_submitted"
            } else {
                "receipt_unverified"
            };

            serde_json::json!({
                "commitment": hex::encode(&ev.commitment),
                "commitment_hex": hex::encode(&ev.commitment),
                "salt_hex": hex::encode(&ev.salt),
                "head_record_cid_hex": hex::encode(&ev.head_record_cid),
                "chain_id": ev.chain_id,
                "contract_address_hex": format!("0x{}", hex::encode(&ev.contract_address)),
                "tx_hash": if is_empty_tx { "".to_string() } else { tx_hex.clone() },
                "tx_hash_hex": tx_hex,
                "explorer_url": arbiscan_url.clone(),
                "arbiscan_url": arbiscan_url,
                "reported_block_number": if ev.block_number > 0 { Some(ev.block_number) } else { None },
                "timestamp_utc": ev.timestamp_utc,
                "is_relayed": !is_empty_tx,
                "confirmed": false,
                "inclusion_verified": false,
                "verification_status": verification_status,
                "status": status_str,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "relayer_status": {
            "operational": null,
            "status": "unverified",
            "target_network": "Arbitrum checkpoint metadata",
            "verification_status": "unavailable"
        },
        "checkpoints": json_anchors,
        "count": anchors.len()
    }))
}

async fn api_relayer_anchor_handler() -> impl axum::response::IntoResponse {
    match cmd_anchor(None, None, None, None, None, None, true, None).await {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "verification_status": "unverified",
            "message": "Checkpoint processing completed. The dashboard has not independently verified a sequencer receipt."
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_fleet_handler() -> impl axum::response::IntoResponse {
    let fleet_db_path = PathBuf::from(".ciphervault").join("fleet.db");
    if !fleet_db_path.exists() {
        return axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "fleet_summary": {
                "total_tracked_vaults": null,
                "healthy_vaults": null,
                "degraded_vaults": null,
                "total_audits_recorded": null,
                "audits_completed": null,
                "online_operators": null,
                "active_operators": null,
                "total_operators": null,
                "avg_latency_ms": null,
            },
            "vaults": [],
            "operator_nodes": [],
            "audit_history": [],
            "message": "No maintenance history is available yet. Run an explicit local audit to create it.",
        }));
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

    // This read route intentionally does not register vaults, probe operators,
    // or write maintenance state. Collection happens during an explicit audit
    // or through the maintenance service, preventing page refreshes from
    // becoming a background mutation and probe loop.
    let summary = db.get_fleet_summary().ok();

    let vaults = db.list_vaults().unwrap_or_default();
    let nodes = db.list_operator_nodes().unwrap_or_default();
    let history = db.get_recent_audits(20).unwrap_or_default();

    let avg_latency = {
        let healthy_nodes: Vec<_> = nodes.iter().filter(|n| n.is_healthy).collect();
        if !healthy_nodes.is_empty() {
            Some(
                healthy_nodes.iter().map(|n| n.latency_ms).sum::<u64>()
                    / healthy_nodes.len() as u64,
            )
        } else {
            None
        }
    };

    let fleet_summary = serde_json::json!({
        "total_tracked_vaults": summary.as_ref().map(|s| s.total_tracked_vaults),
        "healthy_vaults": summary.as_ref().map(|s| s.healthy_vaults),
        "degraded_vaults": summary.as_ref().map(|s| s.degraded_vaults),
        "total_audits_recorded": summary.as_ref().map(|s| s.total_audits_recorded),
        "audits_completed": summary.as_ref().map(|s| s.total_audits_recorded),
        "online_operators": summary.as_ref().map(|s| s.online_operators),
        "active_operators": summary.as_ref().map(|s| s.online_operators),
        "total_operators": summary.as_ref().map(|s| s.total_operators),
        "avg_latency_ms": avg_latency,
    });

    let formatted_nodes: Vec<_> = nodes
        .iter()
        .enumerate()
        .map(|(i, n)| {
            let last_hb = if n.last_seen_utc > 0 {
                Utc.timestamp_opt(n.last_seen_utc as i64, 0)
                    .single()
                    .map(|dt| dt.format("%H:%M:%S UTC").to_string())
                    .unwrap_or_else(|| "Recent".to_string())
            } else {
                "Not reported".to_string()
            };
            serde_json::json!({
                "operator_id": format!("Operator {}", i + 1),
                "endpoint": mask_operator_endpoint(&n.endpoint),
                "status": if n.is_healthy { "Online" } else { "Offline" },
                "is_healthy": n.is_healthy,
                "latency_ms": if n.is_healthy { Some(n.latency_ms) } else { None },
                "last_heartbeat": last_hb,
                "last_seen_utc": n.last_seen_utc,
            })
        })
        .collect();

    let formatted_vaults: Vec<_> = vaults
        .iter()
        .map(|v| {
            let reg_str = if v.registered_at_utc > 0 {
                Utc.timestamp_opt(v.registered_at_utc as i64, 0)
                    .single()
                    .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                    .unwrap_or_else(|| "Recent".to_string())
            } else {
                "Not reported".to_string()
            };
            serde_json::json!({
                "vault_id": v.locator_hex,
                "locator_hex": v.locator_hex,
                "label": v.label,
                "head_cid": null,
                "status": v.last_status,
                "replica_count": v.replica_count,
                "registered_at": reg_str,
                "storage_allowance_bytes": null,
            })
        })
        .collect();

    let formatted_audits: Vec<_> = history
        .iter()
        .map(|a| {
            let audit_time = Utc
                .timestamp_opt(a.timestamp_utc as i64, 0)
                .single()
                .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
                .unwrap_or_else(|| "Recent".to_string());
            serde_json::json!({
                "id": a.id,
                "vault_id": a.locator_hex,
                "status": if a.healthy { "Healthy" } else { "Degraded" },
                "healthy": a.healthy,
                "healthy_objects": a.total_objects.saturating_sub(a.degraded_objects),
                "degraded_objects": a.degraded_objects,
                "repaired_objects": null,
                "timestamp": audit_time,
                "duration_ms": null,
            })
        })
        .collect();

    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "summary": summary,
        "fleet_summary": fleet_summary,
        "vaults": formatted_vaults,
        "operator_nodes": formatted_nodes,
        "audit_history": formatted_audits,
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
                let _ = db.register_vault(&locator_hex, Some("Active Project Vault"));
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
        let http = public_operator_http_client();
        let probes = operators.into_iter().map(|endpoint| {
            let http = http.clone();
            async move {
                let client = OperatorClient::with_http_client(endpoint.clone(), http);
                let start = std::time::Instant::now();
                let (online, latency_ms) = match client.get_info().await {
                    Ok(_) => (true, start.elapsed().as_millis() as u64),
                    Err(_) => (false, 999),
                };
                serde_json::json!({
                    "endpoint": endpoint,
                    "online": online,
                    "latency_ms": latency_ms,
                })
            }
        });
        let op_latencies = join_all(probes).await;

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
    file_path: Option<String>,
    min_size: Option<usize>,
    avg_size: Option<usize>,
    max_size: Option<usize>,
}

const FASTCDC_MAX_INSPECTION_BYTES: usize = 2 * 1024 * 1024;
const FASTCDC_MAX_RESULT_CHUNKS: usize = 512;
const FASTCDC_MAX_CHUNK_SIZE: usize = 1024 * 1024;

fn fastcdc_workspace_root() -> std::result::Result<PathBuf, String> {
    std::env::current_dir()
        .map_err(|_| "Unable to determine the local workspace root.".to_string())?
        .canonicalize()
        .map_err(|_| "Unable to resolve the local workspace root.".to_string())
}

fn canonical_tracked_inspection_file(
    workspace_root: &Path,
    tracked_path: &Path,
) -> std::result::Result<PathBuf, String> {
    let candidate = if tracked_path.is_absolute() {
        tracked_path.to_path_buf()
    } else {
        workspace_root.join(tracked_path)
    };
    let canonical = candidate
        .canonicalize()
        .map_err(|_| "The selected tracked file is unavailable.".to_string())?;

    if !canonical.starts_with(workspace_root) {
        return Err("The selected tracked file is outside the local workspace.".to_string());
    }

    let metadata = fs::metadata(&canonical)
        .map_err(|_| "The selected tracked file is unavailable.".to_string())?;
    if !metadata.is_file() {
        return Err("The selected tracked path is not a regular file.".to_string());
    }

    Ok(canonical)
}

fn resolve_tracked_inspection_file(requested_path: &str) -> std::result::Result<PathBuf, String> {
    let normalized_request = requested_path.trim().replace('\\', "/");
    if normalized_request.is_empty() {
        return Err("Select a tracked vault file before inspecting it.".to_string());
    }

    let store = get_vault_store()
        .map_err(|_| "No initialized local vault is available for file inspection.".to_string())?;
    let tracked = store
        .list_tracked_files()
        .map_err(|_| "Unable to read the tracked-file registry.".to_string())?;
    let selected = tracked
        .iter()
        .find(|(path, _)| path.to_string_lossy().replace('\\', "/") == normalized_request)
        .map(|(path, _)| path)
        .ok_or_else(|| {
            "Select an exact tracked vault file from the local workspace.".to_string()
        })?;

    let workspace_root = fastcdc_workspace_root()?;
    canonical_tracked_inspection_file(&workspace_root, selected)
}

fn fastcdc_config_from_request(
    payload: &FastCdcInspectRequest,
) -> std::result::Result<FastCdcConfig, String> {
    match (payload.min_size, payload.avg_size, payload.max_size) {
        (None, None, None) => Ok(FastCdcConfig::default()),
        (Some(min), Some(avg), Some(max))
            if min >= 64 && min <= avg && avg <= max && max <= FASTCDC_MAX_CHUNK_SIZE =>
        {
            Ok(FastCdcConfig::new(min, avg, max))
        }
        _ => Err(format!(
            "Chunk sizes must satisfy 64 <= min <= average <= max <= {} bytes.",
            FASTCDC_MAX_CHUNK_SIZE
        )),
    }
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

async fn api_fastcdc_vault_files_handler() -> impl axum::response::IntoResponse {
    let workspace_root = fastcdc_workspace_root().ok();
    let files = match get_vault_store() {
        Ok(store) => match store.list_tracked_files() {
            Ok(list) => list
                .into_iter()
                .filter_map(|(path, file_id)| {
                    let root = workspace_root.as_ref()?;
                    let canonical = canonical_tracked_inspection_file(root, &path).ok()?;
                    let size = fs::metadata(&canonical).ok()?.len();
                    Some(serde_json::json!({
                        "path": path.to_string_lossy().replace('\\', "/"),
                        "exists": true,
                        "size_bytes": size,
                        "file_id": hex::encode(&file_id[0..4]),
                    }))
                })
                .collect::<Vec<_>>(),
            Err(_) => Vec::new(),
        },
        Err(_) => Vec::new(),
    };

    axum::Json(serde_json::json!({
        "success": true,
        "files": files,
    }))
}

async fn api_fastcdc_inspect_handler(
    axum::Json(payload): axum::Json<FastCdcInspectRequest>,
) -> impl axum::response::IntoResponse {
    let config = match fastcdc_config_from_request(&payload) {
        Ok(config) => config,
        Err(error) => {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": error,
            }));
        }
    };

    if payload.file_path.is_some() && payload.content.is_some() {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Provide either direct text or one tracked vault file, not both.",
        }));
    }

    let (raw_data, source_label) = if let Some(ref requested_path) = payload.file_path {
        let target = match resolve_tracked_inspection_file(requested_path) {
            Ok(target) => target,
            Err(error) => {
                return axum::Json(serde_json::json!({
                    "success": false,
                    "error": error,
                }));
            }
        };
        match fs::read(&target) {
            Ok(bytes) => (bytes, "Selected tracked vault file".to_string()),
            Err(_) => {
                return axum::Json(serde_json::json!({
                    "success": false,
                    "error": "The selected tracked file is unavailable.",
                }));
            }
        }
    } else if let Some(ref txt) = payload.content {
        if !txt.trim().is_empty() {
            (txt.as_bytes().to_vec(), "Direct text input".to_string())
        } else {
            return axum::Json(serde_json::json!({
                "success": false,
                "error": "Provided text input is empty. Enter text or select a tracked vault file."
            }));
        }
    } else {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": "Enter text or explicitly select a tracked vault file before inspecting chunks.",
        }));
    };

    let max_input_bytes =
        FASTCDC_MAX_INSPECTION_BYTES.min(config.min_size.saturating_mul(FASTCDC_MAX_RESULT_CHUNKS));
    if raw_data.len() > max_input_bytes {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!(
                "Inspection input exceeds the {} byte limit for this chunk-size configuration.",
                max_input_bytes
            ),
        }));
    }

    let chunks = fastcdc_chunk(&raw_data, &config);
    if chunks.len() > FASTCDC_MAX_RESULT_CHUNKS {
        return axum::Json(serde_json::json!({
            "success": false,
            "error": format!(
                "Inspection would return more than {} chunk records. Increase the minimum chunk size or reduce the input.",
                FASTCDC_MAX_RESULT_CHUNKS
            ),
        }));
    }

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
            "preview": "Content previews are disabled.",
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
        "source": source_label,
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

#[derive(serde::Deserialize)]
struct DiffQueryParams {
    snapshot_a: Option<String>,
    snapshot_b: Option<String>,
    file: Option<String>,
    reveal: Option<bool>,
}

async fn api_diff_handler(
    axum::extract::Query(params): axum::extract::Query<DiffQueryParams>,
) -> impl axum::response::IntoResponse {
    let reveal = params.reveal.unwrap_or(false);
    match generate_diff_report(params.snapshot_a, params.snapshot_b, params.file, reveal) {
        Ok(report) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "report": report
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

#[derive(serde::Deserialize)]
struct FileActionPayload {
    path: String,
}

async fn api_files_track_handler(
    axum::Json(payload): axum::Json<FileActionPayload>,
) -> impl axum::response::IntoResponse {
    let p = PathBuf::from(payload.path.trim());
    if !p.exists() {
        return axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": format!("File '{}' does not exist on disk", p.display())
        }));
    }
    match cmd_track(vec![p.clone()], false, false) {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": format!("Tracked file '{}' successfully and appended to .gitignore", p.display())
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_files_untrack_handler(
    axum::Json(payload): axum::Json<FileActionPayload>,
) -> impl axum::response::IntoResponse {
    let p = PathBuf::from(payload.path.trim());
    match cmd_untrack(vec![p.clone()]) {
        Ok(_) => axum::Json(serde_json::json!({
            "status": "ok",
            "success": true,
            "message": format!("Untracked file '{}' successfully", p.display())
        })),
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

#[derive(serde::Deserialize)]
struct RestoreSnapshotPayload {
    snapshot_id: Option<String>,
    to: Option<String>,
    hardware_token: Option<bool>,
    reader: Option<String>,
    pin: Option<String>,
}

async fn api_snapshots_restore_handler(
    axum::Json(payload): axum::Json<RestoreSnapshotPayload>,
) -> impl axum::response::IntoResponse {
    let to_path = payload.to.clone().unwrap_or_else(|| ".".to_string());
    match cmd_restore(
        payload.snapshot_id,
        payload.to.map(PathBuf::from),
        payload.hardware_token.unwrap_or(false),
        payload.reader,
        payload.pin,
    ) {
        Ok(_) => {
            if let Ok(store) = get_vault_store() {
                let _ = store.record_activity(
                    "SNAPSHOT_RESTORE",
                    &format!("Restored snapshot into '{}'", to_path),
                    "{}",
                );
            }
            axum::Json(serde_json::json!({
                "status": "ok",
                "success": true,
                "message": format!("Snapshot restored successfully to '{}'", to_path)
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "success": false,
            "error": e.to_string()
        })),
    }
}

async fn api_snapshot_manifest_handler(
    axum::extract::Path(snap_id_hex): axum::extract::Path<String>,
) -> impl axum::response::IntoResponse {
    let clean_hex = snap_id_hex.trim().trim_start_matches("0x");
    let snap_id_bytes = match hex::decode(clean_hex) {
        Ok(b) if b.len() == 32 => {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&b);
            arr
        }
        _ => {
            return axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "error": "Invalid snapshot ID hex (must be 32 bytes / 64 characters)"
            }));
        }
    };

    let store = match get_vault_store() {
        Ok(s) => s,
        Err(e) => {
            return axum::Json(serde_json::json!({
                "status": "error",
                "success": false,
                "error": format!("Vault store error: {}", e)
            }));
        }
    };

    let vault_id = match store.get_vault_id() {
        Ok(v) => v,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": e.to_string() }),
            );
        }
    };

    let (record, encrypted_manifest) = match store.get_snapshot(&snap_id_bytes) {
        Ok(res) => res,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Snapshot not found: {}", e) }),
            );
        }
    };

    let epoch_key = match store.get_epoch_key(record.epoch) {
        Ok(k) => k,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Failed to retrieve epoch key: {}", e) }),
            );
        }
    };

    let manifest_key = match epoch_key.derive_manifest_key(record.epoch) {
        Ok(k) => k,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": e.to_string() }),
            );
        }
    };

    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();

    let manifest_bytes = match ciphervault_crypto::decrypt_chunk(
        &manifest_key,
        &encrypted_manifest,
        &aad,
    ) {
        Ok(b) => b,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Failed to decrypt manifest: {}", e) }),
            );
        }
    };

    let manifest: SnapshotManifest = match from_canonical_cbor(&manifest_bytes) {
        Ok(m) => m,
        Err(e) => {
            return axum::Json(
                serde_json::json!({ "status": "error", "success": false, "error": format!("Invalid CBOR manifest: {}", e) }),
            );
        }
    };

    let file_items: Vec<_> = manifest
        .files
        .iter()
        .map(|f| {
            let chunk_cids_hex: Vec<String> = f.chunk_cids.iter().map(hex::encode).collect();
            serde_json::json!({
                "path": f.relative_path,
                "size_bytes": f.raw_length,
                "file_id_hex": hex::encode(&f.file_id),
                "chunk_count": f.chunk_cids.len(),
                "chunk_cids": chunk_cids_hex,
                "is_deleted": f.is_deleted,
            })
        })
        .collect();

    let total_bytes: u64 = manifest
        .files
        .iter()
        .filter(|f| !f.is_deleted)
        .map(|f| f.raw_length)
        .sum();

    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "snapshot_id_hex": clean_hex,
        "epoch": record.epoch,
        "device_counter": record.device_counter,
        "timestamp_utc": record.advisory_timestamp_utc,
        "files_count": file_items.len(),
        "total_bytes": total_bytes,
        "files": file_items
    }))
}

async fn api_activity_handler() -> impl axum::response::IntoResponse {
    let store = match get_vault_store() {
        Ok(s) => s,
        Err(_) => {
            return axum::Json(serde_json::json!({
                "status": "ok",
                "events": []
            }));
        }
    };

    let events = store.list_activity(50).unwrap_or_default();
    axum::Json(serde_json::json!({
        "status": "ok",
        "success": true,
        "events": events
    }))
}

async fn api_workspaces_handler() -> impl axum::response::IntoResponse {
    let vaults = discover_workspace_vaults();
    let active_path = get_active_vault_path().display().to_string();
    axum::Json(serde_json::json!({
        "status": "ok",
        "active_workspace_db": active_path,
        "count": vaults.len(),
        "workspaces": vaults
    }))
}

#[derive(serde::Deserialize)]
struct SwitchWorkspaceRequest {
    db_path: Option<String>,
    workspace_path: Option<String>,
}

async fn api_workspaces_switch_handler(
    axum::Json(payload): axum::Json<SwitchWorkspaceRequest>,
) -> impl axum::response::IntoResponse {
    let target_db = if let Some(db) = payload.db_path {
        PathBuf::from(db)
    } else if let Some(ws) = payload.workspace_path {
        PathBuf::from(ws).join(VAULT_DIR).join(DB_FILE)
    } else {
        return axum::Json(serde_json::json!({
            "status": "error",
            "error": "Must provide either 'db_path' or 'workspace_path'"
        }));
    };

    if !target_db.exists() {
        return axum::Json(serde_json::json!({
            "status": "error",
            "error": format!("Vault database does not exist at '{}'", target_db.display())
        }));
    }

    match LocalVaultStore::open(&target_db) {
        Ok(_) => {
            set_active_vault_path(Some(target_db.clone()));
            axum::Json(serde_json::json!({
                "status": "ok",
                "message": format!("Switched active workspace to {}", target_db.display()),
                "active_workspace_db": target_db.display().to_string()
            }))
        }
        Err(e) => axum::Json(serde_json::json!({
            "status": "error",
            "error": format!("Failed to open vault store: {}", e)
        })),
    }
}

async fn api_workspaces_scan_handler() -> impl axum::response::IntoResponse {
    let vaults = discover_workspace_vaults();
    axum::Json(serde_json::json!({
        "status": "ok",
        "message": format!("Discovered {} vault workspace(s)", vaults.len()),
        "count": vaults.len(),
        "workspaces": vaults
    }))
}

#[cfg(test)]
mod ui_router_tests {
    use super::*;
    use axum::http::StatusCode;

    async fn start_public_test_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, public_ui_router()).await.unwrap();
        });
        (server, format!("http://{}", address))
    }

    async fn start_private_test_server() -> (tokio::task::JoinHandle<()>, String) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, private_ui_router()).await.unwrap();
        });
        (server, format!("http://{}", address))
    }

    #[tokio::test]
    async fn public_router_allows_only_explicit_public_api_routes() {
        let (server, base_url) = start_public_test_server().await;
        let client = reqwest::Client::new();

        let context = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(context.status(), StatusCode::OK);

        let context: serde_json::Value = context.json().await.unwrap();
        assert_eq!(context["mode"], "public_explorer");
        assert_eq!(context["access_mode"], "public");
        assert_eq!(context["capabilities"]["vault_workspace"], false);
        assert_eq!(context["capabilities"]["plaintext_inspection"], false);

        let public_vault: serde_json::Value = client
            .get(format!("{base_url}/api/vault"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(public_vault.get("vault_id_hex").is_none());
        assert_eq!(public_vault["private_vault_access"], false);

        let anchors: serde_json::Value = client
            .get(format!("{base_url}/api/anchors"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert!(anchors.as_array().is_some_and(Vec::is_empty));

        let checkpoints: serde_json::Value = client
            .get(format!("{base_url}/api/relayer/checkpoints"))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(
            checkpoints["relayer_status"]["verification_status"],
            "unavailable"
        );
        assert!(checkpoints["message"]
            .as_str()
            .is_some_and(|message| message.contains("signed public checkpoint feed")));

        for uri in [
            "/api/secrets/inspect",
            "/api/guardians",
            "/api/fastcdc/vault-files",
            "/api/snapshots/0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef/manifest",
            "/api/workspaces",
        ] {
            let response = client
                .get(format!("{base_url}{uri}"))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "public explorer unexpectedly exposed {uri}"
            );
        }

        let mutation = client
            .post(format!("{base_url}/api/snapshots"))
            .json(&serde_json::json!({ "message": "must not be accepted" }))
            .send()
            .await
            .unwrap();
        assert_eq!(
            mutation.status(),
            StatusCode::FORBIDDEN,
            "public explorer unexpectedly accepted a snapshot mutation"
        );

        for uri in [
            "/api/guardians/split",
            "/api/guardians/reconstruct",
            "/api/fastcdc/inspect",
            "/api/files/track",
            "/api/files/untrack",
            "/api/snapshots/restore",
        ] {
            let response = client
                .post(format!("{base_url}{uri}"))
                .json(&serde_json::json!({}))
                .send()
                .await
                .unwrap();
            assert_eq!(
                response.status(),
                StatusCode::FORBIDDEN,
                "public explorer unexpectedly exposed private mutation {uri}"
            );
        }

        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn private_router_requires_loopback_origin_for_mutations() {
        let (server, base_url) = start_private_test_server().await;
        let client = reqwest::Client::new();

        let read = client
            .get(format!("{base_url}/api/context"))
            .send()
            .await
            .unwrap();
        assert_eq!(read.status(), StatusCode::OK);
        let set_cookie = read
            .headers()
            .get(axum::http::header::SET_COOKIE)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();
        assert!(set_cookie.starts_with("ciphervault_private_session="));
        assert!(set_cookie.contains("Max-Age=1800"));
        let private_context: serde_json::Value = read.json().await.unwrap();
        assert_eq!(private_context["mode"], "local_private");
        assert_eq!(private_context["session"]["scheme"], "http_only_cookie");
        assert_eq!(private_context["session"]["ttl_seconds"], 1800);
        assert_eq!(
            private_context["session"]["revocation_endpoint"],
            "/api/session/revoke"
        );

        let cross_origin_read = client
            .get(format!("{base_url}/api/context"))
            .header("Origin", "http://evil.example")
            .send()
            .await
            .unwrap();
        assert_eq!(cross_origin_read.status(), StatusCode::FORBIDDEN);

        let missing_origin_mutation = client
            .post(format!("{base_url}/api/unknown"))
            .send()
            .await
            .unwrap();
        assert_eq!(missing_origin_mutation.status(), StatusCode::FORBIDDEN);

        let missing_session = client
            .get(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .send()
            .await
            .unwrap();
        assert_eq!(missing_session.status(), StatusCode::UNAUTHORIZED);

        let session_token = private_ui_session_snapshot().token;
        let same_origin_mutation = client
            .post(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(same_origin_mutation.status(), StatusCode::NOT_FOUND);

        let revoke = client
            .post(format!("{base_url}/api/session/revoke"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(revoke.status(), StatusCode::OK);
        assert_eq!(
            revoke
                .headers()
                .get(axum::http::header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("ciphervault_private_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict")
        );

        let revoked_session = client
            .get(format!("{base_url}/api/unknown"))
            .header("Origin", &base_url)
            .header(
                "Cookie",
                format!("ciphervault_private_session={session_token}"),
            )
            .send()
            .await
            .unwrap();
        assert_eq!(revoked_session.status(), StatusCode::UNAUTHORIZED);

        server.abort();
        let _ = server.await;
    }

    #[test]
    fn signed_public_checkpoint_feed_is_verified_before_publication() {
        let signing_key = ciphervault_crypto::generate_signing_key();
        let checkpoint = PublicCheckpointFeedEntry {
            network: "Arbitrum Sepolia".to_string(),
            chain_id: 421614,
            contract_address_hex: "11".repeat(20),
            commitment_hex: "22".repeat(32),
            head_record_cid_hex: "33".repeat(32),
            tx_hash_hex: Some(format!("0x{}", "44".repeat(32))),
            block_number: Some(123),
            published_at_utc: 1_789_250_000,
        };
        let unsigned = PublicCheckpointFeedUnsigned {
            version: 1,
            issued_at_utc: 1_789_250_001,
            checkpoints: vec![checkpoint.clone()],
        };
        let message = ciphervault_format::to_canonical_cbor(&unsigned).unwrap();
        let signature = ciphervault_crypto::signatures::sign_with_domain(
            &signing_key,
            b"public_checkpoint_feed",
            &message,
        );
        let feed = PublicCheckpointFeedEnvelope {
            version: unsigned.version,
            issued_at_utc: unsigned.issued_at_utc,
            checkpoints: unsigned.checkpoints,
            publisher_key_hex: hex::encode(signing_key.verifying_key().as_bytes()),
            signature_hex: hex::encode(signature),
        };

        let records = verify_public_checkpoint_feed(&feed).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
        assert_eq!(records[0]["finality_status"], "unverified");

        let mut tampered = feed.clone();
        tampered.checkpoints[0].block_number = Some(124);
        assert!(verify_public_checkpoint_feed(&tampered).is_err());
    }

    #[test]
    fn public_operator_identity_requires_independent_pin() {
        let key = ciphervault_crypto::generate_signing_key();
        let key_hex = hex::encode(key.verifying_key().as_bytes());
        assert!(!trusted_public_operator_identity_from_registry(
            "",
            "operator-1",
            &key_hex
        ));
        assert!(trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-1",
            &key_hex,
        ));
        assert!(!trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-2",
            &key_hex,
        ));
        assert!(!trusted_public_operator_identity_from_registry(
            &format!("operator-1={key_hex}"),
            "operator-1",
            &"00".repeat(32),
        ));
        assert!(trusted_public_operator_identity_from_registry(
            &key_hex, "any-id", &key_hex,
        ));
    }

    #[test]
    fn public_feed_publisher_converts_verified_local_evidence() {
        let signing_key = ciphervault_crypto::generate_signing_key();
        let evidence = ciphervault_format::CheckpointEvidence::new(
            [1u8; 32],
            [2u8; 32],
            42161,
            [3u8; 20],
            [4u8; 32],
            987,
            Utc::now().timestamp().max(0) as u64,
        );
        let feed = build_public_checkpoint_feed(
            vec![evidence],
            "Arbitrum One".to_string(),
            &signing_key,
            Utc::now().timestamp().max(0) as u64,
        )
        .unwrap();
        let records = verify_public_checkpoint_feed(&feed).unwrap();
        assert_eq!(records[0]["status"], "Published");
        assert_eq!(records[0]["chain_id"], 42161);
        assert_eq!(records[0]["reported_block_number"], 987);
        assert_eq!(records[0]["verification_status"], "publisher_signed");
    }

    #[test]
    fn local_ui_bind_addresses_are_distinguished_from_public_ones() {
        assert!(parse_ui_host("127.0.0.1").unwrap().is_loopback());
        assert!(parse_ui_host("localhost").unwrap().is_loopback());
        assert!(parse_ui_host("::1").unwrap().is_loopback());
        assert!(!parse_ui_host("0.0.0.0").unwrap().is_loopback());
    }

    #[test]
    fn private_session_rotation_covers_expiry_and_vault_binding() {
        let mut expired = new_private_ui_session(Some("vault-a".to_string()));
        expired.issued_at = Instant::now()
            .checked_sub(PRIVATE_UI_SESSION_TTL + Duration::from_secs(1))
            .expect("test instant should be representable");
        assert!(private_ui_session_should_rotate(
            &expired,
            &Some("vault-a".to_string())
        ));

        let active = new_private_ui_session(Some("vault-a".to_string()));
        assert!(!private_ui_session_should_rotate(
            &active,
            &Some("vault-a".to_string())
        ));
        assert!(private_ui_session_should_rotate(
            &active,
            &Some("vault-b".to_string())
        ));
    }

    #[test]
    fn fastcdc_rejects_oversized_or_invalid_chunk_configuration() {
        let invalid = FastCdcInspectRequest {
            content: Some("sample".to_string()),
            file_path: None,
            min_size: Some(4_096),
            avg_size: Some(2_048),
            max_size: Some(65_536),
        };
        assert!(fastcdc_config_from_request(&invalid).is_err());

        let oversized = FastCdcInspectRequest {
            content: Some("sample".to_string()),
            file_path: None,
            min_size: Some(4_096),
            avg_size: Some(16_384),
            max_size: Some(FASTCDC_MAX_CHUNK_SIZE + 1),
        };
        assert!(fastcdc_config_from_request(&oversized).is_err());
    }

    #[test]
    fn fastcdc_rejects_files_outside_the_workspace() {
        let base = std::env::temp_dir().join(format!(
            "ciphervault-fastcdc-boundary-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let workspace = base.join("workspace");
        let outside = base.join("outside.txt");
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(&outside, "private").unwrap();

        let workspace_root = workspace.canonicalize().unwrap();
        assert!(canonical_tracked_inspection_file(&workspace_root, &outside).is_err());

        let _ = std::fs::remove_dir_all(base);
    }
}
