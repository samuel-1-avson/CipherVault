use anyhow::Result;
use ciphervault_storage::client::OperatorClient;
use clap::Parser;
use colored::*;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "ciphervault-maintenance")]
#[command(author = "CipherVault Contributors")]
#[command(version = "0.1.0")]
#[command(about = "CipherVault Autonomous Replication Audit & Self-Repair Service")]
struct Cli {
    #[arg(short, long, num_args = 1.., help = "Operator endpoints to manage")]
    operators: Vec<String>,

    #[arg(short, long, default_value = "30", help = "Audit interval in seconds")]
    interval_secs: u64,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Autonomous Maintenance Daemon".bold().green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Monitored Operators: {}", cli.operators.len());
    for op in &cli.operators {
        println!("  - {}", op);
    }
    println!("  Audit Interval:      {} seconds", cli.interval_secs);
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
                            let latency = start.elapsed().as_millis();
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
                            println!(
                                "  {} {} — error: {}",
                                "[DEGRADED]".red().bold(),
                                client.endpoint(),
                                e
                            );
                        }
                    }
                }

                if reachable == clients.len() && !clients.is_empty() {
                    println!("  {} Cluster quorum is 100% healthy ({}/{} online)\n", "[STATUS]".cyan(), reachable, clients.len());
                } else {
                    println!("  {} Cluster degraded: {}/{} online\n", "[WARNING]".yellow().bold(), reachable, clients.len());
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
