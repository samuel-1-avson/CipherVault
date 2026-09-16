use clap::Parser;
use colored::*;
use ed25519_dalek::SigningKey;
use std::fs;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

#[derive(Parser, Debug)]
#[command(name = "ciphervault-operator")]
#[command(version)]
#[command(about = "Independent storage operator daemon for CipherVault", long_about = None)]
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
    #[cfg(not(unix))]
    let _ = path;
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
    let app = create_router(state);

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
        assert_eq!(format_identity_registry_entry("op_8201", "ABCD"), "op_8201=ABCD");
    }
}
