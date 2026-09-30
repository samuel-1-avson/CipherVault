use anyhow::Result;
use ciphervault_maintenance::db::MaintenanceDb;
use ciphervault_maintenance::scheduler::{read_inventory, run_inventory_job};
use ciphervault_storage::client::OperatorClient;
use clap::Parser;
use colored::*;
use std::path::PathBuf;
use std::time::Duration;
use zeroize::Zeroizing;

#[derive(Parser)]
#[command(name = "ciphervault-maintenance")]
#[command(author = "CipherVault Contributors")]
#[command(version)]
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

    #[arg(
        long,
        help = "Print fleet metrics in Prometheus exposition format and exit"
    )]
    metrics: bool,

    #[arg(
        long,
        help = "Register a trusted public recovery inventory JSON and exit"
    )]
    register_inventory: Option<PathBuf>,

    #[arg(
        long,
        help = "Optional enrolled device signing key file (32 raw bytes) for repair and renewal"
    )]
    signing_key: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let db = MaintenanceDb::open(&cli.db)?;

    if let Some(path) = &cli.register_inventory {
        let inventory = read_inventory(path)?;
        db.store_inventory(&inventory)?;
        println!(
            "Registered verified inventory for {}",
            hex::encode(inventory.set.locator)
        );
        return Ok(());
    }
    let signing_key = cli
        .signing_key
        .as_ref()
        .map(|path| -> Result<ed25519_dalek::SigningKey> {
            let bytes = Zeroizing::new(std::fs::read(path)?);
            let key: &[u8; 32] = bytes.as_slice().try_into().map_err(|_| {
                anyhow::anyhow!("Signing key file must contain exactly 32 raw bytes")
            })?;
            Ok(ed25519_dalek::SigningKey::from_bytes(key))
        })
        .transpose()?;

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
        println!(
            "  Repairs Recorded:   {} ({} failed)",
            summary.total_repairs_recorded, summary.total_repair_failures
        );
        println!("  Last Repair Lag:    {}s", summary.last_repair_lag_secs);
        return Ok(());
    }

    if cli.metrics {
        let summary = db.get_fleet_summary()?;
        print!("{}", summary.to_prometheus());
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

    let mut clients: Vec<OperatorClient> = cli
        .operators
        .iter()
        .map(|url| OperatorClient::new(url.clone()))
        .collect();
    clients.sort_by(|a, b| a.endpoint().cmp(b.endpoint()));
    clients.dedup_by(|a, b| a.endpoint() == b.endpoint());

    let mut interval = tokio::time::interval(Duration::from_secs(cli.interval_secs.max(1)));
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

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
                                "[REACHABLE]".green(),
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
                    let now = chrono::Utc::now().timestamp().max(0) as u64;
                    if !db.job_due(&vault.locator_hex, now)? { continue; }
                    let Some(mut inventory) = db.get_inventory(&vault.locator_hex)? else {
                        db.record_unverified(&vault.locator_hex, r#"{"verification":"unverified","reason":"trusted recovery inventory required"}"#)?;
                        db.record_job_result(&vault.locator_hex, cli.interval_secs, Some("Trusted recovery inventory required"))?;
                        println!("  [UNVERIFIED] Vault {} [{}]: register a trusted inventory to verify recovery", &vault.locator_hex[..12], vault.label);
                        continue;
                    };
                    match run_inventory_job(&db, &mut inventory, signing_key.as_ref()).await {
                        Ok(report) => {
                            let error = (!report.healthy).then_some("Recovery closure or discovery deficit remains");
                            db.record_job_result(&vault.locator_hex, cli.interval_secs, error)?;
                            println!("  [{}] Vault {} [{}]: {}/{} distinct complete replicas, {} lost objects",
                                if report.healthy { "CLOSURE VERIFIED" } else { "DEGRADED" }, &vault.locator_hex[..12], vault.label,
                                report.recoverable_operators.len(), report.required_replicas, report.objects.lost_count);
                        },
                        Err(error) => {
                            db.record_unverified(&vault.locator_hex, &serde_json::json!({"verification":"unverified", "error":error.to_string()}).to_string())?;
                            db.record_job_result(&vault.locator_hex, cli.interval_secs, Some(&error.to_string()))?;
                            println!("  [UNVERIFIED] Vault {}: {}", &vault.locator_hex[..12], error);
                        },
                    }
                }

                if clients.is_empty() {
                    println!(
                        "  {} No operators configured; fleet cluster is offline\n",
                        "[OFFLINE]".red().bold()
                    );
                } else if reachable == clients.len() {
                    println!(
                        "  {} Cluster reachable ({}/{} online); vault recovery status is reported separately\n",
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
