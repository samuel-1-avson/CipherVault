use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use clap::Parser;
use colored::*;
use ed25519_dalek::SigningKey;
use tokio::net::TcpListener;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::{create_router, OperatorState};

#[derive(Parser, Debug)]
#[command(name = "ciphervault-operator")]
#[command(about = "Independent storage operator daemon for CipherVault", long_about = None)]
struct Args {
    #[arg(short, long, default_value = "8101", help = "Port to listen on")]
    port: u16,

    #[arg(short, long, default_value = "./operator-data", help = "Directory to store immutable ciphertext and recovery logs")]
    data_dir: PathBuf,

    #[arg(short, long, default_value = "operator-1", help = "Operator identifier")]
    operator_id: String,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    fs::create_dir_all(&args.data_dir)?;

    // Load or generate persistent operator signing key
    let key_file = args.data_dir.join("operator.key");
    let signing_key = if key_file.exists() {
        let bytes = fs::read(&key_file)?;
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        SigningKey::from_bytes(&arr)
    } else {
        let sk = generate_signing_key();
        fs::write(&key_file, sk.to_bytes())?;
        sk
    };

    let pk_hex = hex::encode(signing_key.verifying_key().as_bytes());
    let state = Arc::new(OperatorState::new(args.operator_id.clone(), args.data_dir.clone(), signing_key));
    let app = create_router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], args.port));
    println!("{}", "=======================================================".cyan());
    println!("{}", "  CipherVault Independent Storage Operator Daemon".bold().green());
    println!("{}", "=======================================================".cyan());
    println!("  Operator ID:     {}", args.operator_id.yellow());
    println!("  Signing PK:      {}", pk_hex.dimmed());
    println!("  Data Directory:  {}", args.data_dir.display());
    println!("  Listening on:    http://{}", addr);
    println!();

    let listener = TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
