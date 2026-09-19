use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{CommandFactory, Parser, Subcommand};
use colored::*;
use rand::RngCore;
use reqwest::Client as HttpClient;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use axum::response::sse::{Event, KeepAlive, Sse};
use futures_util::{
    future::join_all,
    stream::{self, Stream},
};

use ciphervault_format::{from_canonical_cbor, SnapshotManifest};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_snapshot::{fastcdc_chunk, FastCdcConfig};
use ciphervault_storage::OperatorClient;

mod commands;
mod dashboard;
pub mod diff;
pub mod dotenv;
pub mod tui;
mod util;

pub(crate) use commands::*;
pub(crate) use dashboard::*;
pub(crate) use diff::{cmd_diff, generate_diff_report};
pub(crate) use util::*;

#[derive(Parser)]
#[command(name = "ciphervault")]
#[command(author = "CipherVault Team")]
#[command(version)]
#[command(about = "Decentralized, encrypted version control for confidential files", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Check for and install the latest signed GitHub release for this platform
    Update {
        #[arg(long, help = "Only check the latest release; do not install it")]
        check: bool,
    },

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
    Status {
        #[arg(
            long,
            help = "Emit machine-readable JSON for editor gutter feeds and CI"
        )]
        json: bool,
    },

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

        #[arg(
            long,
            help = "Per-operator object concurrency for replication (1-32, default 4)"
        )]
        concurrency: Option<usize>,

        #[arg(long, help = "Replicas required for quorum (default 3, must be >= 1)")]
        replicas: Option<usize>,
    },

    /// Display snapshot history DAG
    History,

    /// Prune old snapshots per the retention policy (keeps head + unreplicated)
    Prune {
        #[arg(long, help = "Keep at least the N newest snapshots (default 10)")]
        keep_last: Option<usize>,

        #[arg(long, help = "Keep snapshots newer than D days (default 30)")]
        keep_days: Option<u64>,

        #[arg(long, help = "Show what would be pruned without deleting anything")]
        dry_run: bool,
    },

    /// Rotate the vault epoch key (reports ages with --check)
    Rekey {
        #[arg(long, help = "Only report key ages without rotating")]
        check: bool,

        #[arg(
            long,
            help = "Warn when the active epoch key is older than D days (default 90)"
        )]
        warn_days: Option<u64>,
    },

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

        #[arg(long, help = "Replicas required for quorum (default 3, must be >= 1)")]
        replicas: Option<usize>,
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

        #[arg(
            long,
            help = "Inspector mode: report captures without persisting or replicating"
        )]
        dry_run: bool,
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

        #[arg(
            long,
            help = "Mesh routing tables: fetch each operator's self descriptor and announce it to all others"
        )]
        mesh: bool,
    },

    /// Create and renew storage leases on an operator
    Lease {
        #[command(subcommand)]
        sub: LeaseSubcommand,
    },

    /// Issue write vouchers (operator-local administration, service token)
    Voucher {
        #[command(subcommand)]
        sub: VoucherSubcommand,
    },

    /// Out-of-band cryptographic approval and multi-party authorization
    Approve {
        #[command(subcommand)]
        sub: ApproveSubcommand,
    },

    /// Run local self-checks (vault, keyring, operators, quorum, anchors)
    Doctor {
        #[arg(long, help = "Output the report in structured JSON format")]
        json: bool,
    },
}

#[derive(Subcommand)]
enum AuthSubcommand {
    /// Create a local account identity; no vault keys leave this device
    Init {
        #[arg(long, help = "Human-readable account display name")]
        name: Option<String>,
    },

    /// Register this account and the current vault device with the hosted
    /// production account service. Private keys never leave this machine.
    Connect {
        #[arg(
            long,
            default_value = "https://vault.cipherv.online/api/account",
            help = "Hosted account endpoint (the production dashboard proxy by default)"
        )]
        endpoint: String,

        #[arg(
            long,
            default_value = "CipherVault device",
            help = "Label for the enrolled device"
        )]
        label: String,

        #[arg(
            long,
            default_value = "Production vault",
            help = "Alias for the current vault in the hosted account"
        )]
        vault_alias: String,
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
enum LeaseSubcommand {
    /// Commit a storage lease for a closure digest on one operator
    Create {
        #[arg(help = "64-char hex closure digest to lease")]
        closure: String,

        #[arg(help = "Bytes covered by the lease")]
        bytes: u64,

        #[arg(long, default_value = "90", help = "Lease term in days")]
        term_days: u32,

        #[arg(
            short,
            long,
            help = "Target operator endpoint (default: first configured)"
        )]
        operator: Option<String>,
    },

    /// Renew an existing lease for additional days
    Renew {
        #[arg(help = "Lease ID to renew")]
        lease_id: String,

        #[arg(help = "Additional days to extend the lease")]
        days: u32,

        #[arg(help = "Bytes covered by the lease")]
        bytes: u64,

        #[arg(
            short,
            long,
            help = "Target operator endpoint (default: first configured)"
        )]
        operator: Option<String>,
    },
}

#[derive(Subcommand)]
enum VoucherSubcommand {
    /// Issue a write voucher from an operator (needs CIPHERVAULT_OPERATOR_SERVICE_TOKEN)
    Issue {
        #[arg(help = "64-char hex holder public key the voucher is issued to")]
        holder_pk: String,

        #[arg(help = "Byte quota granted by the voucher")]
        quota: u64,

        #[arg(long, default_value = "3600", help = "Voucher TTL in seconds")]
        ttl: u64,

        #[arg(
            short,
            long,
            help = "Issuing operator endpoint (default: first configured)"
        )]
        operator: Option<String>,
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

/// Poll interval used when the TUI is launched implicitly (bare invocation).
const DEFAULT_TUI_POLL_MS: u64 = 3000;

/// Entry point when no subcommand is given: open the interactive TUI on a
/// terminal (covers double-clicked release binaries), otherwise print help.
async fn default_no_subcommand() -> Result<()> {
    if std::io::stdin().is_terminal() {
        tui::run_tui(DEFAULT_TUI_POLL_MS).await
    } else {
        // Same giant-tree hazard as cmd_completions: rendering full help
        // overflows small stacks, so render on a roomy thread.
        std::thread::Builder::new()
            .name("help".into())
            .stack_size(64 * 1024 * 1024)
            .spawn(|| {
                Cli::command().print_help().expect("print help");
                println!();
            })
            .expect("spawn help thread")
            .join()
            .expect("help thread");
        Ok(())
    }
}

async fn run(cli: Cli) -> Result<()> {
    let command = match cli.command {
        Some(command) => command,
        None => return default_no_subcommand().await,
    };
    match command {
        Commands::Update { check } => cmd_update(check).await,
        Commands::Auth { sub } => match sub {
            AuthSubcommand::Init { name } => cmd_auth_init(name),
            AuthSubcommand::Connect {
                endpoint,
                label,
                vault_alias,
            } => cmd_auth_connect(&endpoint, &label, &vault_alias).await,
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
        Commands::Status { json } => cmd_status(json),
        Commands::Push {
            message,
            touch,
            local,
            anchor,
            reader,
            pin,
            concurrency,
            replicas,
        } => {
            cmd_push(
                message,
                touch,
                local,
                anchor,
                reader,
                pin,
                concurrency,
                replicas,
            )
            .await
        }
        Commands::History => cmd_history(),
        Commands::Prune {
            keep_last,
            keep_days,
            dry_run,
        } => cmd_prune(keep_last, keep_days, dry_run),
        Commands::Rekey { check, warn_days } => cmd_rekey(check, warn_days),
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
        Commands::Repair {
            operators,
            replicas,
        } => cmd_repair(operators, replicas).await,
        Commands::Ui {
            host,
            port,
            no_browser,
            local,
            serve,
            url,
        } => cmd_ui(host, port, no_browser, local, serve, url).await,
        Commands::Tui { poll_ms } => tui::run_tui(poll_ms).await,
        Commands::Watch {
            debounce,
            sync,
            dry_run,
        } => cmd_watch(debounce, sync, dry_run).await,
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
        Commands::Peers { discover, mesh } => cmd_peers(discover, mesh).await,
        Commands::Lease { sub } => match sub {
            LeaseSubcommand::Create {
                closure,
                bytes,
                term_days,
                operator,
            } => cmd_lease_create(closure, bytes, term_days, operator).await,
            LeaseSubcommand::Renew {
                lease_id,
                days,
                bytes,
                operator,
            } => cmd_lease_renew(lease_id, days, bytes, operator).await,
        },
        Commands::Voucher { sub } => match sub {
            VoucherSubcommand::Issue {
                holder_pk,
                quota,
                ttl,
                operator,
            } => cmd_voucher_issue(holder_pk, quota, ttl, operator).await,
        },
        Commands::Approve { sub } => match sub {
            ApproveSubcommand::List => cmd_approve_list().await,
            ApproveSubcommand::Sign { challenge_id, name } => {
                cmd_approve_sign(challenge_id, name).await
            }
            ApproveSubcommand::Status { challenge_id } => cmd_approve_status(challenge_id).await,
        },
        Commands::Doctor { json } => cmd_doctor(json).await,
    }
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

/// Release version for update comparison: numeric core plus an optional
/// prerelease suffix (`v1.0.7-beta.1` -> core (1,0,7), pre "beta.1").
/// Splitting the suffix out matters: parsing "7-beta" as a number yields 0,
/// which previously made every prerelease tag compare older than any release.
struct ReleaseVersion {
    core: (u64, u64, u64),
    pre: Option<String>,
}

impl ReleaseVersion {
    fn parse(tag: &str) -> Self {
        let tag = tag.trim().trim_start_matches('v');
        let (core_part, pre_part) = match tag.split_once('-') {
            Some((core, pre)) => (core, Some(pre.to_string())),
            None => (tag, None),
        };
        let mut nums = core_part
            .split('.')
            .map(|part| part.trim().parse::<u64>().unwrap_or(0));
        Self {
            core: (
                nums.next().unwrap_or(0),
                nums.next().unwrap_or(0),
                nums.next().unwrap_or(0),
            ),
            pre: pre_part.filter(|part| !part.is_empty()),
        }
    }

    /// True when `self` is a newer release than `other`, following semver
    /// precedence: a higher core wins; for equal cores a final release beats
    /// any prerelease, and prereleases compare identifier by identifier.
    fn is_newer_than(&self, other: &Self) -> bool {
        if self.core != other.core {
            return self.core > other.core;
        }
        match (&self.pre, &other.pre) {
            (None, None) => false,
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (Some(a), Some(b)) => compare_pre_release(a, b) == std::cmp::Ordering::Greater,
        }
    }
}

/// Compares dot-separated prerelease identifiers with numeric-aware ordering
/// (`beta.2` < `beta.10`); numeric identifiers sort below alphanumeric ones.
fn compare_pre_release(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut a_parts = a.split('.');
    let mut b_parts = b.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

async fn cmd_update(check_only: bool) -> Result<()> {
    let (target, archive_suffix) = match (std::env::consts::OS, std::env::consts::ARCH) {
        ("windows", "x86_64") => ("x86_64-pc-windows-msvc", "zip"),
        ("linux", "x86_64") => ("x86_64-unknown-linux-gnu", "tar.gz"),
        ("linux", "aarch64") => ("aarch64-unknown-linux-gnu", "tar.gz"),
        ("macos", "x86_64") => ("x86_64-apple-darwin", "tar.gz"),
        ("macos", "aarch64") => ("aarch64-apple-darwin", "tar.gz"),
        (os, arch) => bail!("No published CipherVault release for {os}/{arch}"),
    };
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let release: serde_json::Value = client
        .get("https://api.github.com/repos/samuel-1-avson/CipherVault/releases/latest")
        .header("Accept", "application/vnd.github+json")
        .send()
        .await
        .context("checking the CipherVault release feed")?
        .error_for_status()
        .context("GitHub did not return the latest CipherVault release")?
        .json()
        .await
        .context("decoding the CipherVault release feed")?;
    let tag = release
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .context("latest release did not include a tag")?;
    let current = env!("CARGO_PKG_VERSION");
    println!("Current CipherVault: {current}; latest release: {tag}");
    let current_version = ReleaseVersion::parse(current);
    let latest_version = ReleaseVersion::parse(tag);
    if check_only {
        if !latest_version.is_newer_than(&current_version) {
            println!("Already at or ahead of the latest published release.");
        } else {
            println!("Run `ciphervault update` to install the verified release.");
        }
        return Ok(());
    }
    if !latest_version.is_newer_than(&current_version) {
        println!("Already at or ahead of the latest published release.");
        return Ok(());
    }
    let archive_name = format!("ciphervault-{tag}-{target}.{archive_suffix}");
    let sums_name = "SHA256SUMS.txt";
    let base_url = format!("https://github.com/samuel-1-avson/CipherVault/releases/download/{tag}");
    let archive = client
        .get(format!("{base_url}/{archive_name}"))
        .send()
        .await
        .context("downloading the latest CipherVault archive")?
        .error_for_status()
        .context("latest CipherVault archive is unavailable")?
        .bytes()
        .await
        .context("reading the latest CipherVault archive")?;
    let sums = client
        .get(format!("{base_url}/{sums_name}"))
        .send()
        .await
        .context("downloading the CipherVault release checksum")?
        .error_for_status()
        .context("latest CipherVault checksum is unavailable")?
        .text()
        .await
        .context("reading the CipherVault release checksum")?;
    let expected = sums
        .lines()
        .find_map(|line| {
            let mut fields = line.split_whitespace();
            let digest = fields.next()?;
            let name = fields.next()?.trim_start_matches("*");
            (name == archive_name).then_some(digest.to_ascii_lowercase())
        })
        .context("release checksum does not contain the selected archive")?;
    let actual = hex::encode(Sha256::digest(&archive));
    if expected != actual {
        bail!("release checksum mismatch for {archive_name}");
    }

    let temp_root = std::env::temp_dir().join(format!(
        "ciphervault-update-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir_all(&temp_root)?;
    let archive_path = temp_root.join(&archive_name);
    fs::write(&archive_path, &archive)?;
    let extract_dir = temp_root.join("extract");
    fs::create_dir_all(&extract_dir)?;
    #[cfg(windows)]
    {
        let status = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
                &archive_path.to_string_lossy(),
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .context("extracting the Windows release archive")?;
        if !status.success() {
            bail!("Windows release archive extraction failed");
        }
    }
    #[cfg(not(windows))]
    {
        let status = std::process::Command::new("tar")
            .args([
                "-xzf",
                &archive_path.to_string_lossy(),
                "-C",
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .context("extracting the release archive")?;
        if !status.success() {
            bail!("release archive extraction failed");
        }
    }
    let binary_name = if cfg!(windows) {
        "ciphervault.exe"
    } else {
        "ciphervault"
    };
    let extracted_binary = walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_file() && entry.file_name() == binary_name)
        .map(|entry| entry.into_path())
        .context("release archive did not contain the CipherVault CLI")?;
    let current_exe = std::env::current_exe().context("locating the running CipherVault CLI")?;
    #[cfg(windows)]
    {
        let replacement = current_exe.with_extension("exe.new");
        fs::copy(&extracted_binary, &replacement)?;
        let script = current_exe.with_extension("update.cmd");
        let script_body = format!(
            "@echo off\r\n:wait\r\nmove /Y \"{}\" \"{}\" >nul 2>&1\r\nif errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\ndel \"%~f0\"\r\n",
            replacement.display(),
            current_exe.display()
        );
        fs::write(&script, script_body)?;
        std::process::Command::new("cmd.exe")
            .args(["/C", "start", "", "/B", &script.to_string_lossy()])
            .spawn()
            .context("starting the Windows update helper")?;
        println!("Verified {tag}; the new CLI will be installed after this process exits.");
    }
    #[cfg(not(windows))]
    {
        let replacement = current_exe.with_extension("new");
        fs::copy(&extracted_binary, &replacement)?;
        fs::rename(replacement, current_exe)?;
        println!("Verified and installed CipherVault {tag}.");
    }
    let _ = fs::remove_dir_all(temp_root);
    Ok(())
}

async fn cmd_watch(debounce_secs: u64, sync: bool, dry_run: bool) -> Result<()> {
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
    if dry_run {
        println!(
            "  Dry Run:       {}",
            "Enabled (inspector only; nothing will be captured or replicated)".yellow()
        );
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
        dry_run,
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

fn cmd_completions(shell: clap_complete::Shell) {
    // clap_complete renders the whole command tree recursively; with 40+
    // subcommands the debug-build frames exceed the 8 MiB main-thread
    // stack (immediate stack overflow). Generate on a roomy thread.
    std::thread::Builder::new()
        .name("completions".into())
        .stack_size(64 * 1024 * 1024)
        .spawn(move || {
            let mut cmd = Cli::command();
            clap_complete::generate(shell, &mut cmd, "ciphervault", &mut std::io::stdout());
        })
        .expect("spawn completions thread")
        .join()
        .expect("completions thread");
}

/// Resolves `--operator` to a target endpoint, defaulting to the first
/// configured operator.
fn resolve_target_operator(operator: Option<String>) -> Result<String> {
    if let Some(endpoint) = operator {
        return Ok(endpoint);
    }
    get_configured_operators()
        .into_iter()
        .next()
        .context("No operators configured. Run 'ciphervault init' first.")
}

async fn cmd_lease_create(
    closure: String,
    bytes: u64,
    term_days: u32,
    operator: Option<String>,
) -> Result<()> {
    let endpoint = resolve_target_operator(operator)?;
    let digest = hex::decode(closure.trim()).context("closure digest must be hex")?;
    if digest.len() != 32 {
        bail!("closure digest must be 64 hex chars (32 bytes)");
    }
    let mut closure_digest = [0u8; 32];
    closure_digest.copy_from_slice(&digest);
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let client = OperatorClient::new(endpoint);
    let token = client
        .authenticate(&vault_id, &device_sk)
        .await
        .context("device session authentication failed")?;
    let receipt = client
        .commit_lease(&token, &closure_digest, bytes, term_days)
        .await
        .context("lease commit failed")?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

async fn cmd_lease_renew(
    lease_id: String,
    days: u32,
    bytes: u64,
    operator: Option<String>,
) -> Result<()> {
    let endpoint = resolve_target_operator(operator)?;
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let client = OperatorClient::new(endpoint);
    let token = client
        .authenticate(&vault_id, &device_sk)
        .await
        .context("device session authentication failed")?;
    let receipt = client
        .renew_lease(&token, &lease_id, days, bytes)
        .await
        .context("lease renew failed")?;
    println!("{}", serde_json::to_string_pretty(&receipt)?);
    Ok(())
}

async fn cmd_voucher_issue(
    holder_pk: String,
    quota: u64,
    ttl: u64,
    operator: Option<String>,
) -> Result<()> {
    let endpoint = resolve_target_operator(operator)?;
    if std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
        .ok()
        .is_none_or(|value| value.is_empty())
    {
        bail!("CIPHERVAULT_OPERATOR_SERVICE_TOKEN is not set; voucher issuance needs the operator service token");
    }
    let holder = holder_pk.trim();
    if hex::decode(holder).map(|bytes| bytes.len()) != Ok(32) {
        bail!("holder public key must be 64 hex chars (32 bytes)");
    }
    let client = OperatorClient::new(endpoint);
    let voucher = client
        .issue_voucher(holder, quota, ttl)
        .await
        .context("voucher issuance failed")?;
    println!("{}", serde_json::to_string_pretty(&voucher)?);
    Ok(())
}

const UI_INDEX_HTML: &str = include_str!("../../ui/index.html");
const UI_STYLES_CSS: &str = include_str!("../../ui/styles.css");
const UI_APP_JS: &str = include_str!("../../ui/app.js");

// ---- Explorer (blockchain-style read-only browsing) ----

/// Anonymous read bearer for presence probes. CIDs are unguessable
/// capabilities, so a PoS challenge reveals only presence to someone who
/// already knows the CID; object bytes are never fetched or displayed.
const EXPLORER_ANON_TOKEN: &str = "recovery_anonymous";
const EXPLORER_PROBE_TIMEOUT_SECS: u64 = 8;

fn explorer_error_response(
    status: axum::http::StatusCode,
    code: &str,
    message: String,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        status,
        axum::Json(serde_json::json!({
            "status": "error",
            "code": code,
            "error": message,
        })),
    )
        .into_response()
}

fn parse_explorer_cid(raw: &str) -> Option<([u8; 32], String)> {
    let normalized = raw.trim().to_lowercase();
    let bytes = hex::decode(&normalized).ok()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut cid = [0u8; 32];
    cid.copy_from_slice(&bytes);
    Some((cid, normalized))
}

async fn probe_explorer_replica(endpoint: String, cid: [u8; 32]) -> serde_json::Value {
    let started = std::time::Instant::now();
    let mut nonce = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let client = OperatorClient::new(endpoint.clone());
    let outcome = tokio::time::timeout(
        Duration::from_secs(EXPLORER_PROBE_TIMEOUT_SECS),
        client.challenge_object_pos(EXPLORER_ANON_TOKEN, &cid, &nonce),
    )
    .await;
    let latency_ms = started.elapsed().as_millis() as u64;
    match outcome {
        Ok(Ok(receipt)) if receipt.cid_hex == hex::encode(cid) => serde_json::json!({
            "endpoint": endpoint,
            "status": "present",
            "operator_id": receipt.operator_id,
            "size_bytes": receipt.size_bytes,
            "latency_ms": latency_ms,
        }),
        Ok(Ok(_)) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": "PoS receipt CID mismatch",
        }),
        Ok(Err(ciphervault_storage::StorageError::ServerError { status: 404, .. })) => {
            serde_json::json!({
                "endpoint": endpoint,
                "status": "absent",
                "latency_ms": latency_ms,
            })
        }
        Ok(Err(error)) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": error.to_string(),
        }),
        Err(_) => serde_json::json!({
            "endpoint": endpoint,
            "status": "unknown",
            "latency_ms": latency_ms,
            "error": "probe timeout",
        }),
    }
}

async fn api_explorer_object_handler(
    axum::extract::Path(cid_raw): axum::extract::Path<String>,
) -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};
    let Some((cid, cid_hex)) = parse_explorer_cid(&cid_raw) else {
        return explorer_error_response(
            StatusCode::BAD_REQUEST,
            "INVALID_CID",
            format!("Not a 64-character hex content ID: {cid_raw}"),
        );
    };
    let endpoints = get_configured_operators();
    if endpoints.is_empty() {
        return explorer_error_response(
            StatusCode::SERVICE_UNAVAILABLE,
            "NO_OPERATORS_CONFIGURED",
            "Explorer has no operator endpoints configured".to_string(),
        );
    }
    let probes = endpoints
        .into_iter()
        .map(|endpoint| probe_explorer_replica(endpoint, cid));
    let replicas = join_all(probes).await;
    let present = replicas
        .iter()
        .filter(|replica| {
            replica.get("status").and_then(|status| status.as_str()) == Some("present")
        })
        .count();
    let checked = replicas.len();
    let required = ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS;
    axum::Json(serde_json::json!({
        "cid": cid_hex,
        "checked_at_utc": Utc::now().to_rfc3339(),
        "quorum": {
            "present": present,
            "checked": checked,
            "required": required,
            "satisfied": present >= required,
        },
        "replicas": replicas,
        "note": "Presence only: the explorer proves possession via PoS challenge and never fetches object bytes.",
    }))
    .into_response()
}

async fn api_explorer_overview_handler() -> axum::Json<serde_json::Value> {
    let telemetry = public_operator_telemetry().await;
    let total = telemetry.operators.len();
    let reachable = telemetry
        .operators
        .iter()
        .filter(|operator| {
            operator.get("status").and_then(|status| status.as_str()) == Some("reachable")
        })
        .count();
    let checkpoints = load_public_feed_with_finality()
        .await
        .ok()
        .flatten()
        .unwrap_or_default();
    let head = checkpoints
        .first()
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    axum::Json(serde_json::json!({
        "observed_at_utc": telemetry.observed_at.to_rfc3339(),
        "operators": {
            "total": total,
            "reachable": reachable,
        },
        "anchors": {
            "count": checkpoints.len(),
            "head": head,
        },
    }))
}

/// Returns true when the feed publisher key matches the independently pinned
/// publisher key. A feed signature only proves the holder of the embedded key
/// signed it; pinning proves it is the deployment's intended publisher.
/// Unconfigured pinning (`None`) preserves the legacy verify-only behavior.
fn public_checkpoint_publisher_key_pinned(
    feed_key_hex: &str,
    pinned_key_hex: Option<&str>,
) -> bool {
    let Some(pinned) = pinned_key_hex.map(str::trim).filter(|key| !key.is_empty()) else {
        return true;
    };
    let normalize = |key: &str| key.trim().trim_start_matches("0x").to_ascii_lowercase();
    normalize(feed_key_hex) == normalize(pinned)
}

fn pinned_public_checkpoint_publisher_key() -> Option<String> {
    std::env::var("CIPHERVAULT_PUBLIC_CHECKPOINT_PUBLISHER_KEY")
        .ok()
        .map(|key| key.trim().to_string())
        .filter(|key| !key.is_empty())
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
    if !public_checkpoint_publisher_key_pinned(
        &feed.publisher_key_hex,
        pinned_public_checkpoint_publisher_key().as_deref(),
    ) {
        return Err("Public checkpoint publisher key is not the pinned publisher key".to_string());
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

const CHECKPOINT_FINALITY_CACHE_TTL: Duration = Duration::from_secs(60);
const DEFAULT_FINALITY_CONFIRMATIONS: u64 = 12;
const DEFAULT_CHECKPOINT_CANARY_MAX_AGE_SECS: u64 = 24 * 60 * 60;

static CHECKPOINT_RPC_HTTP_CLIENT: OnceLock<HttpClient> = OnceLock::new();

/// Shared client for independent Arbitrum receipt queries. Receipt fetching is
/// read-only evidence collection; RPC failures degrade to `unknown`, never errors.
fn checkpoint_rpc_http_client() -> HttpClient {
    CHECKPOINT_RPC_HTTP_CLIENT
        .get_or_init(|| {
            HttpClient::builder()
                .timeout(Duration::from_secs(10))
                .pool_idle_timeout(Duration::from_secs(120))
                .pool_max_idle_per_host(4)
                .build()
                .unwrap_or_else(|_| HttpClient::new())
        })
        .clone()
}

/// Parses an Ethereum JSON-RPC quantity (`0x`-hex string or JSON number).
fn parse_rpc_quantity(value: &serde_json::Value) -> Option<u64> {
    match value {
        serde_json::Value::String(text) => {
            let digits = text.trim().trim_start_matches("0x");
            if digits.is_empty() || !digits.chars().all(|c| c.is_ascii_hexdigit()) {
                return None;
            }
            u64::from_str_radix(digits, 16).ok()
        }
        serde_json::Value::Number(number) => number.as_u64(),
        _ => None,
    }
}

/// Outcome of one independent `eth_getTransactionReceipt` observation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ReceiptFetch {
    /// The transaction has no receipt yet (pending or unknown to the node).
    Pending,
    /// Receipt observed; `status_ok` mirrors receipt `status` (1 = success).
    Observed { status_ok: bool, block_number: u64 },
    /// RPC failed or returned an unparseable receipt; evidence unavailable.
    Failed,
}

/// Classifies a JSON-RPC `result` for `eth_getTransactionReceipt`.
fn classify_receipt_result(result: &serde_json::Value) -> ReceiptFetch {
    if result.is_null() {
        return ReceiptFetch::Pending;
    }
    let receipt = match result.as_object() {
        Some(object) => object,
        None => return ReceiptFetch::Failed,
    };
    let status = receipt.get("status").and_then(parse_rpc_quantity);
    let block_number = receipt.get("blockNumber").and_then(parse_rpc_quantity);
    match (status, block_number) {
        (Some(status), Some(block_number)) => ReceiptFetch::Observed {
            status_ok: status == 1,
            block_number,
        },
        _ => ReceiptFetch::Failed,
    }
}

/// Maps one receipt observation + chain tip to
/// `(finality_status, receipt_block, confirmations)`.
fn checkpoint_finality(
    fetch: ReceiptFetch,
    tip_block: Option<u64>,
    required_confirmations: u64,
) -> (&'static str, Option<u64>, Option<u64>) {
    match fetch {
        ReceiptFetch::Pending => ("pending", None, None),
        ReceiptFetch::Failed => ("unknown", None, None),
        ReceiptFetch::Observed {
            status_ok: false,
            block_number,
        } => (
            "failed",
            Some(block_number),
            tip_block.map(|tip| tip.saturating_sub(block_number)),
        ),
        ReceiptFetch::Observed {
            status_ok: true,
            block_number,
        } => {
            let confirmations = tip_block.map(|tip| tip.saturating_sub(block_number));
            let finalized = confirmations.is_some_and(|count| count >= required_confirmations);
            (
                if finalized { "finalized" } else { "confirmed" },
                Some(block_number),
                confirmations,
            )
        }
    }
}

/// Detects reorg suspects among previously-finalized receipts: a suspect is a
/// feed checkpoint whose finalized receipt is now missing or mined at a
/// different block. `current` carries (tx hash, finality status, receipt block).
/// Checkpoints that left the feed are ignored (feed edits are not reorgs), and
/// a re-finalized receipt clears even at a new block (the chain moved on).
fn detect_reorg_suspects(
    previously_finalized: &[(String, u64)],
    current: &[(String, String, Option<u64>)],
) -> Vec<String> {
    previously_finalized
        .iter()
        .filter(|(tx, block)| {
            let Some((_, status, observed)) =
                current.iter().find(|(current_tx, _, _)| current_tx == tx)
            else {
                return false;
            };
            if status == "finalized" {
                return false;
            }
            match observed {
                Some(observed_block) => observed_block != block,
                None => true,
            }
        })
        .map(|(tx, _)| tx.clone())
        .collect()
}

fn finality_confirmations_required() -> u64 {
    std::env::var("CIPHERVAULT_FINALITY_CONFIRMATIONS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|confirmations| *confirmations > 0)
        .unwrap_or(DEFAULT_FINALITY_CONFIRMATIONS)
}

fn checkpoint_canary_max_age_secs() -> u64 {
    std::env::var("CIPHERVAULT_CHECKPOINT_CANARY_MAX_AGE_SECS")
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|max_age| *max_age > 0)
        .unwrap_or(DEFAULT_CHECKPOINT_CANARY_MAX_AGE_SECS)
}

/// Canary over checkpoint freshness: `ok` when the newest checkpoint is within
/// `max_age_secs`, `stale` when older, `missing` when no checkpoint exists.
fn checkpoint_canary_status(
    newest_published_at_utc: Option<u64>,
    now_utc: u64,
    max_age_secs: u64,
) -> &'static str {
    match newest_published_at_utc {
        None => "missing",
        Some(published) if now_utc.saturating_sub(published) <= max_age_secs => "ok",
        Some(_) => "stale",
    }
}

fn newest_checkpoint_published_at(checkpoints: &[serde_json::Value]) -> Option<u64> {
    checkpoints
        .iter()
        .filter_map(|checkpoint| checkpoint.get("published_at_utc")?.as_u64())
        .max()
}

async fn fetch_receipt_observation(
    client: &HttpClient,
    rpc_url: &str,
    tx_hash_hex: String,
) -> ReceiptFetch {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_getTransactionReceipt",
        "params": [tx_hash_hex],
    });
    let response = match client.post(rpc_url).json(&body).send().await {
        Ok(response) => response,
        Err(_) => return ReceiptFetch::Failed,
    };
    let payload: serde_json::Value = match response.json().await {
        Ok(payload) => payload,
        Err(_) => return ReceiptFetch::Failed,
    };
    if payload.get("error").is_some() {
        return ReceiptFetch::Failed;
    }
    match payload.get("result") {
        Some(result) => classify_receipt_result(result),
        None => ReceiptFetch::Failed,
    }
}

async fn fetch_chain_tip_block(client: &HttpClient, rpc_url: &str) -> Option<u64> {
    let body = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "eth_blockNumber",
        "params": [],
    });
    let response = client.post(rpc_url).json(&body).send().await.ok()?;
    let payload: serde_json::Value = response.json().await.ok()?;
    if payload.get("error").is_some() {
        return None;
    }
    payload.get("result").and_then(parse_rpc_quantity)
}

static CHECKPOINT_FINALITY_CACHE: OnceLock<tokio::sync::Mutex<Option<FinalityCacheEntry>>> =
    OnceLock::new();

#[derive(Clone)]
struct FinalityCacheEntry {
    cached_at: Instant,
    checkpoints: Vec<serde_json::Value>,
    /// Previously-finalized receipts as (tx hash, block): reorg memory.
    finalized: Vec<(String, u64)>,
}

/// Loads the verified feed and, when `CIPHERVAULT_ARBITRUM_RPC_URL` is set,
/// enriches transaction-bearing checkpoints with independent receipt finality.
/// Results are cached briefly; without an RPC URL this is the plain feed.
async fn load_public_feed_with_finality() -> Result<Option<Vec<serde_json::Value>>, String> {
    let checkpoints = match load_public_checkpoint_feed()? {
        Some(checkpoints) => checkpoints,
        None => return Ok(None),
    };
    let rpc_url = std::env::var("CIPHERVAULT_ARBITRUM_RPC_URL")
        .ok()
        .map(|url| url.trim().to_string())
        .filter(|url| !url.is_empty());
    let Some(rpc_url) = rpc_url else {
        return Ok(Some(checkpoints));
    };

    let cache = CHECKPOINT_FINALITY_CACHE.get_or_init(|| tokio::sync::Mutex::new(None));
    let previous_finalized = match cache.lock().await.clone() {
        Some(entry) if entry.cached_at.elapsed() < CHECKPOINT_FINALITY_CACHE_TTL => {
            return Ok(Some(entry.checkpoints));
        }
        Some(entry) => entry.finalized,
        None => Vec::new(),
    };

    let client = checkpoint_rpc_http_client();
    let required = finality_confirmations_required();
    let tip = fetch_chain_tip_block(&client, &rpc_url).await;
    let tx_hashes: Vec<Option<String>> = checkpoints
        .iter()
        .map(|checkpoint| {
            checkpoint
                .get("tx_hash_hex")
                .and_then(|hash| hash.as_str())
                .filter(|hash| !hash.is_empty())
                .map(str::to_string)
        })
        .collect();
    let targets: Vec<(usize, String)> = tx_hashes
        .iter()
        .enumerate()
        .filter_map(|(index, hash)| hash.clone().map(|hash| (index, hash)))
        .collect();
    let mut enriched = checkpoints;
    for chunk in targets.chunks(8) {
        let fetches = chunk
            .iter()
            .map(|(_, hash)| fetch_receipt_observation(&client, &rpc_url, hash.clone()));
        let observations = join_all(fetches).await;
        for ((index, _), fetch) in chunk.iter().zip(observations) {
            let (status, block, confirmations) = checkpoint_finality(fetch, tip, required);
            let Some(record) = enriched.get_mut(*index) else {
                continue;
            };
            let Some(object) = record.as_object_mut() else {
                continue;
            };
            object.insert("finality_status".to_string(), serde_json::json!(status));
            object.insert("receipt_block_number".to_string(), serde_json::json!(block));
            object.insert(
                "confirmations".to_string(),
                serde_json::json!(confirmations),
            );
        }
    }

    let current: Vec<(String, String, Option<u64>)> = enriched
        .iter()
        .filter_map(|record| {
            let tx = record
                .get("tx_hash_hex")?
                .as_str()
                .filter(|hash| !hash.is_empty())?;
            let status = record
                .get("finality_status")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let block = record
                .get("receipt_block_number")
                .and_then(|value| value.as_u64());
            Some((tx.to_string(), status.to_string(), block))
        })
        .collect();
    let suspects = detect_reorg_suspects(&previous_finalized, &current);
    for record in enriched.iter_mut() {
        let tx = record
            .get("tx_hash_hex")
            .and_then(|hash| hash.as_str())
            .unwrap_or("");
        if suspects.iter().any(|suspect| suspect == tx) {
            if let Some(object) = record.as_object_mut() {
                object.insert(
                    "finality_status".to_string(),
                    serde_json::json!("reorg_suspected"),
                );
            }
        }
    }
    for tx in &suspects {
        eprintln!("checkpoint reorg suspected: finalized receipt for {tx} missing or re-mined");
    }
    let mut next_finalized: Vec<(String, u64)> = Vec::new();
    for (tx, status, block) in &current {
        if status == "finalized" {
            if let Some(number) = block {
                next_finalized.push((tx.clone(), *number));
            }
        }
    }
    // Suspects stay in memory so the alarm persists until re-finalized; feed
    // removals drop out (feed edits are not reorgs).
    for (tx, block) in &previous_finalized {
        if current.iter().any(|(current_tx, _, _)| current_tx == tx)
            && !next_finalized.iter().any(|(known, _)| known == tx)
        {
            next_finalized.push((tx.clone(), *block));
        }
    }

    let entry = FinalityCacheEntry {
        cached_at: Instant::now(),
        checkpoints: enriched.clone(),
        finalized: next_finalized,
    };
    *cache.lock().await = Some(entry);
    Ok(Some(enriched))
}

async fn api_public_anchors_handler() -> axum::response::Response {
    use axum::{http::StatusCode, response::IntoResponse};

    match load_public_feed_with_finality().await {
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

    match load_public_feed_with_finality().await {
        Ok(Some(checkpoints)) => {
            let checkpoint_count = checkpoints.len();
            let network = checkpoints
                .first()
                .and_then(|checkpoint| checkpoint.get("network"))
                .and_then(|network| network.as_str())
                .unwrap_or("Published checkpoint feed");
            let newest_checkpoint = newest_checkpoint_published_at(&checkpoints);
            let now_utc = Utc::now().timestamp().max(0) as u64;
            let canary_max_age = checkpoint_canary_max_age_secs();
            let canary = checkpoint_canary_status(newest_checkpoint, now_utc, canary_max_age);
            let reorg_suspect_tx_hashes: Vec<String> = checkpoints
                .iter()
                .filter(|checkpoint| {
                    checkpoint.get("finality_status").and_then(|status| status.as_str())
                        == Some("reorg_suspected")
                })
                .filter_map(|checkpoint| {
                    checkpoint.get("tx_hash_hex")?.as_str().map(str::to_string)
                })
                .collect();
            let rpc_configured = std::env::var("CIPHERVAULT_ARBITRUM_RPC_URL")
                .ok()
                .is_some_and(|url| !url.trim().is_empty());
            axum::Json(serde_json::json!({
                "status": "ok",
                "access_mode": "public",
                "relayer_status": {
                    "public_read_only": true,
                    "target_network": network,
                    "verification_status": "publisher_signed",
                    "finality_status": if rpc_configured { "independent_rpc" } else { "unverified" },
                    "canary_status": canary,
                    "reorg_suspected": !reorg_suspect_tx_hashes.is_empty(),
                    "reorg_suspect_tx_hashes": reorg_suspect_tx_hashes,
                    "canary_max_age_secs": canary_max_age,
                    "newest_checkpoint_at_utc": newest_checkpoint,
                },
                "checkpoints": checkpoints,
                "count": checkpoint_count,
                "message": "Checkpoint records are signed by the configured publisher; per-checkpoint finality reflects independent RPC receipts when an Arbitrum RPC URL is configured.",
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
                "canary_status": "missing",
                "newest_checkpoint_at_utc": serde_json::Value::Null,
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
                    "canary_status": "missing",
                    "newest_checkpoint_at_utc": serde_json::Value::Null,
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
mod update_version_tests {
    use super::*;

    fn offers_update(current: &str, latest_tag: &str) -> bool {
        ReleaseVersion::parse(latest_tag).is_newer_than(&ReleaseVersion::parse(current))
    }

    #[test]
    fn prerelease_tag_with_higher_core_is_offered() {
        // Regression: "7-beta" used to parse as 0, so v1.0.7-beta.1 compared
        // older than 1.0.6 and no user was ever offered the beta.
        assert!(offers_update("1.0.6", "v1.0.7-beta.1"));
        assert_eq!(ReleaseVersion::parse("v1.0.7-beta.1").core, (1, 0, 7));
    }

    #[test]
    fn same_prerelease_is_not_offered() {
        assert!(!offers_update("1.0.7-beta.1", "v1.0.7-beta.1"));
    }

    #[test]
    fn prerelease_moves_forward_within_pre_suffix() {
        assert!(offers_update("1.0.7-beta.1", "v1.0.7-beta.2"));
        // Numeric identifiers compare numerically, not lexicographically.
        assert!(offers_update("1.0.7-beta.2", "v1.0.7-beta.10"));
        assert!(!offers_update("1.0.7-beta.10", "v1.0.7-beta.2"));
    }

    #[test]
    fn final_release_beats_its_prerelease_but_never_downgrades() {
        assert!(offers_update("1.0.7-beta.1", "v1.0.7"));
        assert!(!offers_update("1.0.7", "v1.0.7-beta.1"));
    }

    #[test]
    fn plain_release_comparison_still_works() {
        assert!(offers_update("1.0.6", "v1.0.7"));
        assert!(!offers_update("1.0.6", "v1.0.6"));
        assert!(!offers_update("1.0.7", "v1.0.6"));
    }
}

#[cfg(test)]
mod ui_router_tests {
    use super::*;

    #[test]
    fn explorer_cid_parser_normalizes_and_validates() {
        let (bytes, normalized) = parse_explorer_cid(&"AB".repeat(32)).unwrap();
        assert_eq!(normalized, "ab".repeat(32));
        assert_eq!(bytes, [0xabu8; 32]);
        assert!(parse_explorer_cid("  ab12  ").is_none());
        assert!(parse_explorer_cid(&"ab".repeat(31)).is_none());
        assert!(parse_explorer_cid(&"zz".repeat(32)).is_none());
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
    fn reorg_alarm_fires_on_finalized_receipt_regression() {
        let previous = vec![("0xaaa".to_string(), 100u64), ("0xbbb".to_string(), 120u64)];
        // Vanished receipt + re-mined receipt alarm; steady ones stay quiet.
        let current = vec![
            ("0xaaa".to_string(), "unknown".to_string(), None),
            ("0xbbb".to_string(), "confirmed".to_string(), Some(125u64)),
        ];
        assert_eq!(
            detect_reorg_suspects(&previous, &current),
            vec!["0xaaa".to_string(), "0xbbb".to_string()]
        );
        // Still finalized, or confirmed at the same block: no alarm.
        let current = vec![
            ("0xaaa".to_string(), "finalized".to_string(), Some(100u64)),
            ("0xbbb".to_string(), "confirmed".to_string(), Some(120u64)),
        ];
        assert!(detect_reorg_suspects(&previous, &current).is_empty());
        // Re-finalized at a new block clears; feed removals never alarm.
        let current = vec![("0xaaa".to_string(), "finalized".to_string(), Some(140u64))];
        assert!(detect_reorg_suspects(&previous, &current).is_empty());
    }

    #[test]
    fn checkpoint_publisher_pinning_matches_exact_key_only() {
        let key = "ab".repeat(32);
        assert!(public_checkpoint_publisher_key_pinned(&key, None));
        assert!(public_checkpoint_publisher_key_pinned(&key, Some("")));
        assert!(public_checkpoint_publisher_key_pinned(&key, Some(&key)));
        assert!(public_checkpoint_publisher_key_pinned(
            &key,
            Some(&format!("0x{key}"))
        ));
        assert!(public_checkpoint_publisher_key_pinned(
            &key,
            Some(&key.to_ascii_uppercase())
        ));
        assert!(!public_checkpoint_publisher_key_pinned(
            &key,
            Some(&"00".repeat(32))
        ));
    }

    #[test]
    fn receipt_quantities_and_finality_classification() {
        assert_eq!(parse_rpc_quantity(&serde_json::json!("0x10")), Some(16));
        assert_eq!(parse_rpc_quantity(&serde_json::json!("0x0")), Some(0));
        assert_eq!(parse_rpc_quantity(&serde_json::json!(7)), Some(7));
        assert_eq!(parse_rpc_quantity(&serde_json::json!("zz")), None);
        assert_eq!(parse_rpc_quantity(&serde_json::Value::Null), None);
        assert_eq!(
            classify_receipt_result(&serde_json::Value::Null),
            ReceiptFetch::Pending
        );
        let observed = serde_json::json!({"status": "0x1", "blockNumber": "0x64"});
        assert_eq!(
            classify_receipt_result(&observed),
            ReceiptFetch::Observed {
                status_ok: true,
                block_number: 100
            }
        );
        let failed_tx = serde_json::json!({"status": "0x0", "blockNumber": "0x64"});
        assert_eq!(
            classify_receipt_result(&failed_tx),
            ReceiptFetch::Observed {
                status_ok: false,
                block_number: 100
            }
        );
        assert_eq!(
            classify_receipt_result(&serde_json::json!({"blockNumber": "0x64"})),
            ReceiptFetch::Failed
        );
        assert_eq!(
            checkpoint_finality(ReceiptFetch::Pending, Some(200), 12).0,
            "pending"
        );
        assert_eq!(
            checkpoint_finality(ReceiptFetch::Failed, Some(200), 12).0,
            "unknown"
        );
        let obs = ReceiptFetch::Observed {
            status_ok: true,
            block_number: 100,
        };
        assert_eq!(checkpoint_finality(obs, Some(200), 12).0, "finalized");
        assert_eq!(checkpoint_finality(obs, Some(105), 12).0, "confirmed");
        assert_eq!(checkpoint_finality(obs, None, 12).0, "confirmed");
        let reverted = ReceiptFetch::Observed {
            status_ok: false,
            block_number: 100,
        };
        assert_eq!(checkpoint_finality(reverted, Some(200), 12).0, "failed");
    }

    #[test]
    fn checkpoint_canary_tracks_freshness() {
        let now = 2_000_000_000u64;
        assert_eq!(checkpoint_canary_status(None, now, 3_600), "missing");
        assert_eq!(checkpoint_canary_status(Some(now - 100), now, 3_600), "ok");
        assert_eq!(
            checkpoint_canary_status(Some(now - 3_600), now, 3_600),
            "ok"
        );
        assert_eq!(
            checkpoint_canary_status(Some(now - 3_601), now, 3_600),
            "stale"
        );
        assert_eq!(checkpoint_canary_status(Some(now + 60), now, 3_600), "ok");
    }

    #[test]
    fn newest_checkpoint_selects_max_timestamp() {
        let checkpoints = serde_json::json!([
            {"published_at_utc": 10},
            {"published_at_utc": 30},
            {"published_at_utc": 20},
        ]);
        let list = checkpoints.as_array().unwrap().clone();
        assert_eq!(newest_checkpoint_published_at(&list), Some(30));
        assert_eq!(newest_checkpoint_published_at(&[]), None);
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

    #[test]
    fn lease_voucher_peers_mesh_args_parse() {
        use clap::Parser;
        let cli = Cli::try_parse_from([
            "ciphervault",
            "lease",
            "create",
            &"ab".repeat(32),
            "4096",
            "--term-days",
            "30",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Lease {
                sub: LeaseSubcommand::Create {
                    bytes: 4096,
                    term_days: 30,
                    ..
                }
            })
        ));
        let cli =
            Cli::try_parse_from(["ciphervault", "lease", "renew", "lease-1", "7", "4096"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Lease {
                sub: LeaseSubcommand::Renew { days: 7, .. }
            })
        ));
        let cli =
            Cli::try_parse_from(["ciphervault", "voucher", "issue", &"cd".repeat(32), "8192"])
                .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Voucher {
                sub: VoucherSubcommand::Issue {
                    quota: 8192,
                    ttl: 3600,
                    ..
                }
            })
        ));
        let cli = Cli::try_parse_from(["ciphervault", "peers", "--mesh"]).unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Peers { mesh: true, .. })
        ));
    }
}

#[cfg(test)]
mod entry_tests {
    use super::*;

    #[test]
    fn bare_invocation_parses_to_no_subcommand() {
        // Regression: a bare `ciphervault` (e.g. double-clicked release
        // binary) used to be a clap error and the window vanished. It must
        // parse so the entry point can open the TUI or print help.
        let cli = Cli::try_parse_from(["ciphervault"]).expect("bare invocation must parse");
        assert!(cli.command.is_none());
    }

    #[test]
    fn explicit_subcommand_still_parses() {
        let cli = Cli::try_parse_from(["ciphervault", "tui"]).expect("tui must parse");
        assert!(matches!(cli.command, Some(Commands::Tui { .. })));
    }
}
