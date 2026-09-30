use ciphervault_account::{create_router, AccountState};
use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(
    name = "ciphervault-account",
    version,
    about = "CipherVault account service and offline recovery tools"
)]
struct Cli {
    #[command(subcommand)]
    command: Option<MaintenanceCommand>,
}

#[derive(Subcommand)]
enum MaintenanceCommand {
    /// Consistently back up an existing database into a new protected directory.
    Backup {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        output_dir: PathBuf,
    },
    /// Verify an isolated restore with separately supplied keys; never serves HTTP.
    RestoreRehearsal {
        #[arg(long)]
        backup_dir: PathBuf,
        #[arg(long)]
        output_dir: PathBuf,
        #[arg(long)]
        kek_file: Option<PathBuf>,
        #[arg(long)]
        totp_key_file: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();
    let data_dir = std::env::var_os("CIPHERVAULT_ACCOUNT_DATA_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from("./account-data"));
    match cli.command {
        Some(MaintenanceCommand::Backup {
            data_dir: source,
            output_dir,
        }) => {
            let report = ciphervault_account::disaster_recovery::backup_accounts(
                &source.unwrap_or(data_dir),
                &output_dir,
            )?;
            println!("{}", serde_json::to_string(&report)?);
            return Ok(());
        }
        Some(MaintenanceCommand::RestoreRehearsal {
            backup_dir,
            output_dir,
            kek_file,
            totp_key_file,
        }) => {
            let report = ciphervault_account::disaster_recovery::rehearse_restore(
                &backup_dir,
                &output_dir,
                kek_file.as_deref(),
                totp_key_file.as_deref(),
            )?;
            println!("{}", serde_json::to_string(&report)?);
            return Ok(());
        }
        None => {}
    }
    let bind =
        std::env::var("CIPHERVAULT_ACCOUNT_BIND").unwrap_or_else(|_| "127.0.0.1:8300".into());
    let state = AccountState::open(data_dir)?;
    let listener = tokio::net::TcpListener::bind(&bind).await?;
    println!("CipherVault account service listening on http://{bind}");
    axum::serve(listener, create_router(state)).await?;
    Ok(())
}
