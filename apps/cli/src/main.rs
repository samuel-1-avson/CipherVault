use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::{CommandFactory, Parser, Subcommand};
use colored::*;
use std::fs;
use std::io::IsTerminal;
use std::path::PathBuf;

use ciphervault_local_store::LocalVaultStore;
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

        #[arg(short, long, num_args = 1.., help = "Custom operator endpoints (default: public fleet; checked for reachability)")]
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

    /// Fleet-signed join invites for new operator nodes
    Invite {
        #[command(subcommand)]
        sub: InviteSubcommand,
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
enum InviteSubcommand {
    /// Print the fleet public key for a seed file (pin as CIPHERVAULT_FLEET_KEY)
    Pubkey {
        #[arg(long, help = "Path to the 32-byte fleet signing seed file")]
        fleet_key_file: PathBuf,
    },

    /// Issue a fleet-signed join invite for a node key (fully offline)
    Issue {
        #[arg(help = "64-char hex node public key the invite is issued to")]
        node_pk: String,

        #[arg(long, default_value = "86400", help = "Invite TTL in seconds")]
        ttl: u64,

        #[arg(long, help = "Path to the 32-byte fleet signing seed file")]
        fleet_key_file: PathBuf,
    },

    /// Present a join ticket to fleet nodes (admits this node into probation)
    Join {
        #[arg(help = "Path to the JSON invite ticket file")]
        ticket: PathBuf,

        #[arg(long, help = "Own node endpoint (fetches our fresh descriptor)")]
        node: String,

        #[arg(
            long,
            num_args = 1..,
            help = "Fleet endpoints to join via (default: configured operators)"
        )]
        via: Option<Vec<String>>,
    },

    /// Re-present our descriptor to fleet nodes (liveness for graduation)
    Refresh {
        #[arg(long, help = "Own node endpoint (fetches our fresh descriptor)")]
        node: String,

        #[arg(
            long,
            num_args = 1..,
            help = "Fleet endpoints to refresh via (default: configured operators)"
        )]
        via: Option<Vec<String>>,
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
        } => {
            cmd_init(
                force,
                operators,
                save_kit,
                hardware_token,
                import_gitignore,
                reader,
                pin,
            )
            .await
        }
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
        Commands::Invite { sub } => match sub {
            InviteSubcommand::Pubkey { fleet_key_file } => cmd_invite_pubkey(fleet_key_file),
            InviteSubcommand::Issue {
                node_pk,
                ttl,
                fleet_key_file,
            } => cmd_invite_issue(node_pk, ttl, fleet_key_file),
            InviteSubcommand::Join { ticket, node, via } => {
                cmd_invite_join(ticket, node, via).await
            }
            InviteSubcommand::Refresh { node, via } => cmd_invite_refresh(node, via).await,
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

#[cfg(test)]
mod ui_router_tests {
    use super::*;

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
        expired.issued_at = std::time::Instant::now()
            .checked_sub(PRIVATE_UI_SESSION_TTL + std::time::Duration::from_secs(1))
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
        let cli = Cli::try_parse_from([
            "ciphervault",
            "invite",
            "pubkey",
            "--fleet-key-file",
            "fleet.seed",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Invite {
                sub: InviteSubcommand::Pubkey { .. }
            })
        ));
        let cli = Cli::try_parse_from([
            "ciphervault",
            "invite",
            "issue",
            &"ef".repeat(32),
            "--fleet-key-file",
            "fleet.seed",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Invite {
                sub: InviteSubcommand::Issue { ttl: 86400, .. }
            })
        ));
        let cli = Cli::try_parse_from([
            "ciphervault",
            "invite",
            "join",
            "ticket.json",
            "--node",
            "http://127.0.0.1:8301",
            "--via",
            "http://127.0.0.1:8201",
            "http://127.0.0.1:8202",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Invite {
                sub: InviteSubcommand::Join { .. }
            })
        ));
        let cli = Cli::try_parse_from([
            "ciphervault",
            "invite",
            "refresh",
            "--node",
            "http://127.0.0.1:8301",
        ])
        .unwrap();
        assert!(matches!(
            cli.command,
            Some(Commands::Invite {
                sub: InviteSubcommand::Refresh { .. }
            })
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
