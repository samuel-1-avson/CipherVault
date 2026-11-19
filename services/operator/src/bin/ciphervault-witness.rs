//! Standalone `c2sp.org/tlog-witness` server (ADR-014 Phase 3).
//!
//! The same witness the operator runs at `/v1/witness`, without the
//! storage operator around it, for people who want to witness CipherVault
//! logs (or any log with an Ed25519 checkpoint key) without running an
//! operator. It cosigns with ML-DSA-44 and keeps its state in
//! `<data dir>/witness/`, in the same layout as the operator's witness.
//!
//! It has no authentication and no rate limiting of its own: put it
//! behind a reverse proxy that limits request rates.

use std::path::PathBuf;
use std::sync::Arc;

use axum::routing::get;
use axum::Router;
use clap::Parser;
use tokio::net::TcpListener;

use ciphervault_operator::witness_api::{self, WitnessService};
use ciphervault_operator::witness_store::{WitnessConfig, WitnessStore};

#[derive(Parser, Debug)]
#[command(
    name = "ciphervault-witness",
    version,
    about = "Standalone c2sp.org/tlog-witness server that cosigns checkpoints with ML-DSA-44"
)]
struct Args {
    #[arg(
        long,
        default_value = "./ciphervault-witness-data",
        help = "State directory"
    )]
    data_dir: PathBuf,

    #[arg(long, default_value = "127.0.0.1:8190", help = "Address to listen on")]
    listen: String,

    #[arg(
        long,
        help = "Witness name, for example witness.example.org/w1 (or CIPHERVAULT_WITNESS_NAME). Pinned on first run."
    )]
    name: Option<String>,

    #[arg(
        long = "trusted-log",
        help = "Ed25519 verifier key of a log to cosign; its key name is the log origin. Repeatable; adds to CIPHERVAULT_WITNESS_TRUSTED_LOGS."
    )]
    trusted_logs: Vec<String>,

    #[arg(
        long,
        default_value_t = false,
        help = "Print the witness name and verifier key, then exit"
    )]
    print_key: bool,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let mut config = WitnessConfig::from_env();
    config.enabled = true;
    if let Some(name) = args.name {
        config.name = Some(name);
    }
    config.trusted_logs.extend(args.trusted_logs);
    if config.name.is_none() {
        return Err("a standalone witness needs --name (or CIPHERVAULT_WITNESS_NAME)".into());
    }

    std::fs::create_dir_all(&args.data_dir)?;
    let store = WitnessStore::open(&args.data_dir, &config, "standalone")?;
    if args.print_key {
        println!("name={}", store.name());
        println!("verifier_key={}", store.verifier_key());
        return Ok(());
    }
    if store.trusted_origins().is_empty() {
        eprintln!("WARNING: no trusted logs configured; every add-checkpoint will answer 404");
    }
    println!(
        "ciphervault-witness {}: {} (key {}), cosigning {} log(s)",
        env!("CARGO_PKG_VERSION"),
        store.name(),
        store.verifier_key(),
        store.trusted_origins().len()
    );

    let service = Arc::new(WitnessService::running(store));
    let app = Router::new()
        .nest_service("/v1/witness", witness_api::router(service))
        .route("/healthz", get(|| async { "ok" }));
    let listener = TcpListener::bind(&args.listen).await?;
    // Tests and supervisors read this line to learn the bound address.
    println!("listening on http://{}", listener.local_addr()?);
    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await?;
    Ok(())
}
