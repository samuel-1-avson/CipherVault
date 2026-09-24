use clap::{Parser, Subcommand};
use colored::*;
use ed25519_dalek::SigningKey;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::swarm::behaviour::{
    OperatorRpcBody, OperatorRpcRequest, OperatorRpcResponse, P2pAuth,
};
use ciphervault_operator::swarm::liveness::{
    DEFAULT_HEARTBEAT_INTERVAL, DEFAULT_HEARTBEAT_TIMEOUT,
};
use ciphervault_operator::swarm::repair::RepairConfig;
use ciphervault_operator::swarm::{boot_swarm, SwarmNodeConfig};
use ciphervault_operator::{create_router, OperatorState};

#[derive(Parser, Debug)]
#[command(name = "ciphervault-operator")]
#[command(version)]
#[command(about = "Independent storage operator daemon for CipherVault")]
#[command(
    long_about = "Independent storage operator daemon for CipherVault.\n\nThis is the expert interface for node runners. For guided setup\n(walkthrough, background supervision, plain-language status), run\n`ciphervault node setup` from the developer CLI instead."
)]
struct Args {
    #[arg(short, long, default_value = "8101", help = "Port to listen on")]
    port: u16,

    #[arg(
        short,
        long,
        default_value = "./operator-data",
        help = "Directory to store immutable ciphertext and recovery logs"
    )]
    data_dir: PathBuf,

    #[arg(
        short,
        long,
        default_value = "operator-1",
        help = "Operator identifier"
    )]
    operator_id: String,

    #[arg(
        long,
        help = "Rotate the persistent signing key after moving the old key to a timestamped backup"
    )]
    rotate_key: bool,

    #[arg(
        long,
        help = "Print the persistent operator identity registry entry and exit without binding"
    )]
    print_identity: bool,

    #[arg(
        long,
        default_value_t = false,
        help = "Start the libp2p swarm alongside the HTTP API (dual mode)"
    )]
    enable_p2p: bool,

    #[arg(
        long,
        default_value = "9101",
        help = "TCP listen port for the P2P swarm"
    )]
    p2p_tcp_port: u16,

    #[arg(
        long,
        default_value = "9102",
        help = "QUIC listen port for the P2P swarm"
    )]
    p2p_quic_port: u16,

    #[arg(long, help = "Bootstrap peer multiaddr, repeatable")]
    p2p_bootstrap: Vec<String>,

    #[arg(
        long,
        help = "Reachable address to advertise (rendezvous registration), repeatable"
    )]
    p2p_advertise_addr: Vec<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Run a circuit-relay server (dedicated relay/seed nodes only)"
    )]
    p2p_relay_server: bool,

    #[arg(
        long,
        help = "Signed JSON bootstrap list for first contact (requires --p2p-bootstrap-signer)"
    )]
    p2p_bootstrap_list: Option<PathBuf>,

    #[arg(
        long,
        help = "Pinned fleet key (hex) that must have signed --p2p-bootstrap-list"
    )]
    p2p_bootstrap_signer: Option<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Run a rendezvous server (dedicated seed nodes only)"
    )]
    p2p_rendezvous_server: bool,

    #[arg(
        long,
        help = "Reserve a relay circuit on this peer-qualified relay multiaddr, repeatable (drill/diagnostics)"
    )]
    p2p_relay_reserve: Vec<String>,

    #[arg(
        long,
        help = "Probe this peer ID after boot (wait for connection, run GetInfo RPC, log result), repeatable (drill/diagnostics)"
    )]
    p2p_probe_peer: Vec<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Require write vouchers on all writes (D4 mesh/testnet policy; static default off)"
    )]
    require_write_vouchers: bool,

    #[arg(
        long,
        default_value_t = 0,
        help = "Uniform per-user (voucher holder key) lifetime write cap in bytes; 0 = unlimited. Aggregates spend across all of a holder's vouchers so chained grants cannot fill disk."
    )]
    user_quota_bytes: u64,

    #[command(subcommand)]
    command: Option<OperatorCommand>,
}

#[derive(Subcommand, Debug)]
enum OperatorCommand {
    /// Sign a bootstrap list with a 32-byte operator seed key and print the
    /// JSON list to stdout for fleet distribution.
    SignBootstrapList {
        #[arg(long, help = "Path to the 32-byte fleet signing seed")]
        key_file: PathBuf,
        /// Bootstrap multiaddrs to include in the list.
        addrs: Vec<String>,
    },
}

fn run_command(command: OperatorCommand) -> Result<(), Box<dyn std::error::Error>> {
    match command {
        OperatorCommand::SignBootstrapList { key_file, addrs } => {
            let bytes = fs::read(&key_file)?;
            if bytes.len() != 32 {
                return Err("signing key file must contain exactly 32 bytes".into());
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            let key = SigningKey::from_bytes(&arr);
            let mut list = ciphervault_operator::swarm::bootstrap::BootstrapList::unsigned(addrs);
            list.sign(&key);
            println!("{}", serde_json::to_string_pretty(&list)?);
            Ok(())
        }
    }
}

fn write_private_key(path: &std::path::Path, bytes: &[u8; 32]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

fn ensure_private_key_permissions(path: &std::path::Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let mode = fs::metadata(path)?.permissions().mode();
        if mode & 0o077 != 0 {
            fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        }
        let final_mode = fs::metadata(path)?.permissions().mode();
        if final_mode & 0o077 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "operator signing key must not be group/world readable",
            ));
        }
    }
    // Windows: protected user-only DACL via the shared crate. Best-effort
    // with a loud warning: filesystems without ACLs must not brick the
    // daemon, but any exposure must be visible.
    #[cfg(windows)]
    if let Err(error) = ciphervault_file_lock::lock_secret_file(path) {
        eprintln!(
            "{}",
            format!(
                "Warning: could not lock down {} ({error}); anyone with disk access may read it.",
                path.display()
            )
            .yellow()
        );
    }
    Ok(())
}

/// Formats the `operator-id=public-key-hex` trust-registry entry printed by
/// `--print-identity` for `CIPHERVAULT_TRUSTED_OPERATOR_IDENTITIES`.
fn format_identity_registry_entry(operator_id: &str, public_key_hex: &str) -> String {
    format!("{operator_id}={public_key_hex}")
}

fn strict_auth_enabled() -> bool {
    std::env::var("CIPHERVAULT_OPERATOR_STRICT_AUTH")
        .ok()
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "1" | "true" | "yes"
            )
        })
        .unwrap_or(true)
}

fn validate_security_configuration() -> io::Result<()> {
    if strict_auth_enabled()
        && std::env::var("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
            .ok()
            .is_none_or(|token| token.trim().is_empty())
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "strict operator auth requires CIPHERVAULT_OPERATOR_SERVICE_TOKEN",
        ));
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    if let Some(command) = args.command {
        return run_command(command);
    }

    if !args.print_identity {
        validate_security_configuration()?;
    }

    fs::create_dir_all(&args.data_dir)?;

    // Load or generate persistent operator signing key
    let key_file = args.data_dir.join("operator.key");
    if args.rotate_key && key_file.exists() {
        let backup = args.data_dir.join(format!(
            "operator.key.previous-{}",
            chrono::Utc::now().format("%Y%m%d%H%M%S")
        ));
        fs::rename(&key_file, backup)?;
    }
    let signing_key = if key_file.exists() {
        ensure_private_key_permissions(&key_file)?;
        let bytes = fs::read(&key_file)?;
        if bytes.len() != 32 {
            return Err("operator signing key must contain exactly 32 bytes".into());
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        SigningKey::from_bytes(&arr)
    } else {
        let sk = generate_signing_key();
        write_private_key(&key_file, &sk.to_bytes())?;
        sk
    };
    ensure_private_key_permissions(&key_file)?;

    let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
    if args.print_identity {
        println!(
            "{}",
            format_identity_registry_entry(&args.operator_id, &pk_hex)
        );
        return Ok(());
    }
    let state = Arc::new(OperatorState::new(
        args.operator_id.clone(),
        args.data_dir.clone(),
        signing_key,
    ));
    if args.require_write_vouchers {
        state.set_vouchers_required(true);
        println!("  Write vouchers: required (D4)");
    }
    if args.user_quota_bytes > 0 {
        state.set_user_quota_bytes(args.user_quota_bytes);
        println!(
            "  User quota: {} bytes lifetime per holder",
            args.user_quota_bytes
        );
    }
    let app = create_router(state.clone());

    // Dual mode: the swarm borrows the same live store as the HTTP API.
    // The handle is held for the daemon's lifetime; dropping it would stop
    // the node.
    let _p2p = if args.enable_p2p {
        let bootstrap = args
            .p2p_bootstrap
            .iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<_>, _>>()?;
        let advertise_addrs = args
            .p2p_advertise_addr
            .iter()
            .map(|addr| addr.parse())
            .collect::<Result<Vec<_>, _>>()?;
        let (handle, _task) = boot_swarm(
            SwarmNodeConfig {
                key_path: args.data_dir.join("swarm.key"),
                tcp_listen: format!("/ip4/0.0.0.0/tcp/{}", args.p2p_tcp_port).parse()?,
                quic_listen: format!("/ip4/0.0.0.0/udp/{}/quic-v1", args.p2p_quic_port).parse()?,
                bootstrap,
                enable_mdns: true,
                enable_relay_server: args.p2p_relay_server,
                enable_dcutr: true,
                bootstrap_list_path: args.p2p_bootstrap_list.clone(),
                bootstrap_signer_hex: args.p2p_bootstrap_signer.clone(),
                enable_rendezvous_server: args.p2p_rendezvous_server,
                advertise_addrs,
                max_established_connections: None,
                max_established_per_peer: None,
                blocked_peers: Vec::new(),
                max_rpc_per_sec_per_peer: None,
                heartbeat_interval: DEFAULT_HEARTBEAT_INTERVAL,
                heartbeat_timeout: DEFAULT_HEARTBEAT_TIMEOUT,
                repair: RepairConfig::default(),
            },
            state.clone(),
        )
        .await
        .map_err(|e| format!("failed to boot P2P swarm: {e}"))?;
        state.set_swarm_handle(handle.clone());
        println!("  P2P Peer ID:     {}", handle.peer_id);
        for addr in handle.listeners().await.unwrap_or_default() {
            println!("  P2P Listening:   {addr}");
        }
        for relay in &args.p2p_relay_reserve {
            let relay_addr: libp2p::Multiaddr = relay
                .parse()
                .map_err(|e| format!("bad --p2p-relay-reserve addr {relay:?}: {e}"))?;
            let relay_peer = relay_addr
                .iter()
                .find_map(|p| match p {
                    libp2p::multiaddr::Protocol::P2p(id) => Some(id),
                    _ => None,
                })
                .ok_or_else(|| {
                    format!(
                        "bad --p2p-relay-reserve addr {relay:?} (want peer-qualified relay addr)"
                    )
                })?;
            // The reservation needs a live connection first (a circuit
            // listen issued mid-dial fails fast); dial explicitly so the
            // flag works without --p2p-bootstrap.
            handle
                .dial(relay_addr)
                .await
                .map_err(|e| format!("relay dial failed: {e}"))?;
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                if handle.is_connected(relay_peer).await.unwrap_or(false) {
                    break;
                }
                if Instant::now() > deadline {
                    return Err(format!("never connected to relay {relay_peer}").into());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            let circuit: libp2p::Multiaddr = format!("{relay}/p2p-circuit")
                .parse()
                .map_err(|e| format!("bad circuit addr for {relay:?}: {e}"))?;
            handle
                .listen_on(circuit)
                .await
                .map_err(|e| format!("relay reservation failed: {e}"))?;
            let deadline = Instant::now() + Duration::from_secs(20);
            loop {
                let listeners = handle.listeners().await.unwrap_or_default();
                if let Some(addr) = listeners
                    .iter()
                    .find(|a| a.to_string().contains("p2p-circuit"))
                {
                    println!("  P2P relay circuit: {addr}");
                    break;
                }
                if Instant::now() > deadline {
                    return Err("relay reservation never accepted".into());
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        }
        for peer_str in &args.p2p_probe_peer {
            let peer: libp2p::PeerId = peer_str
                .parse()
                .map_err(|e| format!("bad --p2p-probe-peer ID {peer_str:?}: {e}"))?;
            let probe_handle = handle.clone();
            tokio::spawn(async move {
                let deadline = Instant::now() + Duration::from_secs(60);
                loop {
                    match probe_handle.is_connected(peer).await {
                        Ok(true) => break,
                        _ => {
                            if Instant::now() > deadline {
                                println!("P2P probe {peer}: never connected");
                                return;
                            }
                            tokio::time::sleep(Duration::from_millis(200)).await;
                        }
                    }
                }
                match probe_handle
                    .rpc_request(
                        peer,
                        OperatorRpcRequest {
                            auth: P2pAuth::default(),
                            body: OperatorRpcBody::GetInfo,
                        },
                    )
                    .await
                {
                    Ok(OperatorRpcResponse::Info(info)) => {
                        println!("P2P probe {peer}: OK operator={}", info.operator_id)
                    }
                    Ok(other) => println!("P2P probe {peer}: unexpected {other:?}"),
                    Err(e) => println!("P2P probe {peer}: RPC failed: {e}"),
                }
            });
        }
        Some(handle)
    } else {
        None
    };

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Independent Storage Operator Daemon"
            .bold()
            .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Operator ID:     {}", args.operator_id.yellow());
    println!("  Signing PK:      {}", pk_hex.dimmed());
    println!("  Data Directory:  {}", args.data_dir.display());
    println!("  Listening on:    http://{}", addr);
    println!();

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

#[cfg(test)]
mod identity_tests {
    use super::format_identity_registry_entry;

    #[test]
    fn registry_entry_pairs_operator_id_with_public_key() {
        assert_eq!(
            format_identity_registry_entry("op_8201", "ABCD"),
            "op_8201=ABCD"
        );
    }

    // Lockdown itself is covered by the ciphervault-file-lock crate tests
    // (same strict property: user-only, no inherited groups).
    #[cfg(windows)]
    #[test]
    fn windows_key_permissions_keep_operator_startable() {
        // ensure_private_key_permissions must stay best-effort on Windows:
        // even on failure it returns Ok so the daemon never bricks.
        let path = std::env::temp_dir().join(format!(
            "cv-op-perm-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, "secret").unwrap();
        super::ensure_private_key_permissions(&path).unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        std::fs::remove_file(&path).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_lockdown_grants_only_current_user() {
        let path = std::env::temp_dir().join(format!(
            "cv-op-restrict-{}-{}.txt",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        std::fs::write(&path, "secret").unwrap();
        // Forward-slash form must work: callers pass Rust display paths.
        let slashed = path.to_string_lossy().replace('\\', "/");
        ciphervault_file_lock::lock_secret_file(std::path::Path::new(&slashed))
            .expect("lockdown must succeed");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "secret");
        let query = std::process::Command::new("icacls")
            .arg(&path)
            .stdin(std::process::Stdio::null())
            .output()
            .unwrap();
        let listing = String::from_utf8_lossy(&query.stdout).to_ascii_lowercase();
        let user = std::env::var("USERNAME").unwrap().to_ascii_lowercase();
        assert!(
            listing.contains(&user),
            "lockdown should grant {user}: {listing}"
        );
        assert!(
            !listing.contains("builtin"),
            "lockdown should strip inherited groups: {listing}"
        );
        std::fs::remove_file(&path).unwrap();
    }
}
