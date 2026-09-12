use anyhow::Result;
use ciphervault_maintenance::db::MaintenanceDb;
use ciphervault_storage::client::OperatorClient;
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "ciphervault-maintenance")]
#[command(author = "CipherVault Contributors")]
#[command(version = "0.1.0")]
#[command(about = "CipherVault Autonomous Replication Audit & Persisted Fleet Scheduler")]
struct Cli {
    #[arg(short, long, num_args = 0.., help = "Operator endpoints to manage")]
    operators: Vec<String>,

    #[arg(short, long, default_value = "30", help = "Audit interval in seconds")]
    interval_secs: u64,

    #[arg(
        long,
        default_value = "maintenance.db",
        help = "Path to persistent SQLite fleet database"
    )]
    db: PathBuf,

    #[arg(
        long,
        help = "Register a vault locator (64 hex characters) for automated fleet maintenance"
    )]
    register_vault: Option<String>,

    #[arg(long, help = "Optional label when registering a vault")]
    vault_label: Option<String>,

    #[arg(long, help = "List all tracked vaults and exit")]
    list_vaults: bool,

    #[arg(long, help = "Display fleet summary status and exit")]
    fleet_status: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = MaintenanceDb::open(&cli.db)?;

    // Handle immediate CLI commands
    if let Some(locator) = cli.register_vault {
        let label = cli.vault_label.as_deref().unwrap_or("Production Vault");
        db.register_vault(&locator, Some(label))?;
        println!(
            "{}",
            format!(
                "✓ Registered vault locator 0x{} ('{}') in fleet database",
                locator, label
            )
            .green()
            .bold()
        );
        return Ok(());
    }

    if cli.list_vaults {
        let vaults = db.list_vaults()?;
        println!("{}", "CipherVault Tracked Fleet Vaults".bold());
        println!(
            "--------------------------------------------------------------------------------"
        );
        if vaults.is_empty() {
            println!("No vaults currently registered in fleet database.");
            println!(
                "Register a vault using: ciphervault-maintenance --register-vault <LOCATOR_HEX>"
            );
        } else {
            for v in vaults {
                println!(
                    "  {} [{}] — Status: {} — Target Replicas: {}",
                    v.locator_hex.yellow(),
                    v.label.cyan(),
                    v.last_status.green(),
                    v.replica_count
                );
                if let Some(ts) = v.last_audit_at_utc {
                    println!("    Last Audit: UTC {}", ts);
                }
            }
        }
        return Ok(());
    }

    if cli.fleet_status {
        let summary = db.get_fleet_summary()?;
        println!("{}", "CipherVault Maintenance Fleet Status Summary".bold());
        println!(
            "--------------------------------------------------------------------------------"
        );
        println!("  Tracked Vaults:     {}", summary.total_tracked_vaults);
        println!(
            "  Healthy Vaults:     {}",
            summary.healthy_vaults.to_string().green()
        );
        println!(
            "  Degraded Vaults:    {}",
            summary.degraded_vaults.to_string().red()
        );
        println!("  Total Audits Run:   {}", summary.total_audits_recorded);
        println!(
            "  Operators Online:   {}/{}",
            summary.online_operators.to_string().cyan(),
            summary.total_operators
        );
        println!(
            "  Fleet Database:     {}",
            cli.db.display().to_string().dimmed()
        );
        return Ok(());
    }

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Autonomous Maintenance Fleet Daemon"
            .bold()
            .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Fleet Database:      {}", cli.db.display());
    println!("  Monitored Operators: {}", cli.operators.len());
    for op in &cli.operators {
        println!("  - {}", op);
    }
    println!("  Audit Interval:      {} seconds", cli.interval_secs);

    let initial_vaults = db.list_vaults()?;
    println!("  Tracked Vaults:      {}", initial_vaults.len());
    for v in &initial_vaults {
        println!("  - {} [{}]", v.locator_hex.yellow(), v.label.dimmed());
    }

    println!(
        "{}",
        "\nDaemon running. Press Ctrl+C to terminate.\n".dimmed()
    );

    let clients: Vec<OperatorClient> = cli
        .operators
        .iter()
        .map(|url| OperatorClient::new(url.clone()))
        .collect();

    let mut interval = tokio::time::interval(Duration::from_secs(cli.interval_secs));

    loop {
        tokio::select! {
            _ = interval.tick() => {
                let now = chrono::Utc::now().to_rfc3339();
                println!("{} Running health audit across {} operators...", format!("[{}]", now).dimmed(), clients.len());
                let mut reachable = 0;

                for client in &clients {
                    let start = std::time::Instant::now();
                    match client.get_info().await {
                        Ok(info) => {
                            reachable += 1;
                            let latency = start.elapsed().as_millis() as u64;
                            let _ = db.update_operator_health(client.endpoint(), latency, true);
                            println!(
                                "  {} {} ({}) — {}ms — terms: '{}'",
                                "[HEALTHY]".green(),
                                info.operator_id.yellow(),
                                client.endpoint(),
                                latency,
                                info.retention_terms
                            );
                        }
                        Err(e) => {
                            let _ = db.update_operator_health(client.endpoint(), 0, false);
                            println!(
                                "  {} {} — error: {}",
                                "[DEGRADED]".red().bold(),
                                client.endpoint(),
                                e
                            );
                        }
                    }
                }

                // Audit all tracked vaults from SQLite database
                let tracked_vaults = db.list_vaults().unwrap_or_default();
                for vault in &tracked_vaults {
                    let mut locator_bytes = [0u8; 32];
                    if let Ok(b) = hex::decode(&vault.locator_hex) {
                        if b.len() == 32 {
                            locator_bytes.copy_from_slice(&b);
                        }
                    }

                    let mut copies_found = 0;
                    for client in &clients {
                        if let Ok(records) = client.get_recovery_records(&locator_bytes).await {
                            if !records.is_empty() {
                                copies_found += 1;
                            }
                        }
                    }

                    let is_healthy = !clients.is_empty()
                        && reachable >= vault.replica_count
                        && copies_found >= vault.replica_count;
                    let details = format!(
                        r#"{{"copies_found": {}, "target_replicas": {}, "operators_scanned": {}, "operators_online": {}}}"#,
                        copies_found, vault.replica_count, clients.len(), reachable
                    );
                    let _ = db.record_audit(
                        &vault.locator_hex,
                        is_healthy,
                        copies_found,
                        0,
                        &details,
                    );

                    if is_healthy {
                        println!(
                            "  {} Vault {} [{}] replicated on {}/{} operators",
                            "[VAULT OK]".green(),
                            vault.locator_hex[..12].yellow(),
                            vault.label,
                            copies_found,
                            clients.len()
                        );
                    } else if clients.is_empty() || reachable == 0 {
                        println!(
                            "  {} Vault {} [{}] unreachable (no online operators)",
                            "[VAULT OFFLINE]".red().bold(),
                            vault.locator_hex[..12].yellow(),
                            vault.label
                        );
                    } else {
                        println!(
                            "  {} Vault {} [{}] replication degraded ({}/{} copies on {}/{} online ops)",
                            "[VAULT DEGRADED]".red().bold(),
                            vault.locator_hex[..12].yellow(),
                            vault.label,
                            copies_found,
                            vault.replica_count,
                            reachable,
                            clients.len()
                        );
                    }
                }

                if clients.is_empty() {
                    println!(
                        "  {} No operators configured; fleet cluster is offline\n",
                        "[OFFLINE]".red().bold()
                    );
                } else if reachable == clients.len() {
                    println!(
                        "  {} Cluster quorum is 100% healthy ({}/{} online)\n",
                        "[STATUS]".cyan(),
                        reachable,
                        clients.len()
                    );
                } else {
                    println!(
                        "  {} Cluster degraded: {}/{} online\n",
                        "[WARNING]".yellow().bold(),
                        reachable,
                        clients.len()
                    );
                }
            }
            _ = tokio::signal::ctrl_c() => {
                println!("\nShutting down maintenance daemon cleanly.");
                break;
            }
        }
    }

    Ok(())
}
