use anyhow::Result;
use clap::Parser;
use colored::*;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use ciphervault_agent::{LocalGuardian, VaultWatcher, WatcherConfig};

#[derive(Parser)]
#[command(name = "ciphervault-agent")]
#[command(author = "CipherVault Contributors")]
#[command(version)]
#[command(about = "CipherVault Background File Watcher & Automated Sync Agent")]
struct Cli {
    #[arg(
        short,
        long,
        help = "Path to vault working directory (defaults to current directory)"
    )]
    dir: Option<PathBuf>,

    #[arg(short, long, help = "Path to agent configuration file")]
    config: Option<PathBuf>,

    #[arg(short, long, default_value = "5", help = "Debounce window in seconds")]
    debounce_secs: u64,

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

    #[arg(
        long,
        help = "Also run the local Guardian secret-sprawl scanner periodically (or set CIPHERVAULT_GUARDIAN=1)"
    )]
    guardian: bool,
}

fn load_operators(vault_root: &Path) -> Vec<String> {
    let config_path = vault_root.join(".ciphervault").join("operators.json");
    if config_path.exists() {
        if let Ok(content) = fs::read_to_string(config_path) {
            if let Ok(ops) = serde_json::from_str::<Vec<String>>(&content) {
                return ops;
            }
        }
    }
    vec![
        "http://127.0.0.1:8101".into(),
        "http://127.0.0.1:8102".into(),
        "http://127.0.0.1:8103".into(),
    ]
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let (config_dir, config_debounce, config_sync) = if let Some(ref cfg_path) = cli.config {
        if cfg_path.exists() {
            let content = fs::read_to_string(cfg_path).unwrap_or_default();
            let mut dir_opt = None;
            let mut deb_opt = None;
            let mut sync_opt = None;
            for line in content.lines() {
                let trimmed = line.trim();
                if let Some(val) = trimmed.strip_prefix("dir =") {
                    dir_opt = Some(PathBuf::from(val.trim().trim_matches('"')));
                } else if let Some(val) = trimmed.strip_prefix("vault_dir =") {
                    dir_opt = Some(PathBuf::from(val.trim().trim_matches('"')));
                } else if let Some(val) = trimmed.strip_prefix("debounce_secs =") {
                    if let Ok(d) = val.trim().parse::<u64>() {
                        deb_opt = Some(d);
                    }
                } else if let Some(val) = trimmed.strip_prefix("sync =") {
                    sync_opt = Some(val.trim() == "true");
                }
            }
            (dir_opt, deb_opt, sync_opt)
        } else {
            (None, None, None)
        }
    } else {
        (None, None, None)
    };

    let root_dir = cli
        .dir
        .or(config_dir)
        .unwrap_or_else(|| std::env::current_dir().expect("agent working dir must exist"));
    let debounce_secs = if cli.debounce_secs != 5 {
        cli.debounce_secs
    } else {
        config_debounce.unwrap_or(cli.debounce_secs)
    };
    let sync = cli.sync || config_sync.unwrap_or(false);

    let vault_db = root_dir.join(".ciphervault").join("vault.db");
    if !vault_db.exists() {
        eprintln!(
            "{} No CipherVault found in '{}'. Run 'ciphervault init' first.",
            "Error:".bold().red(),
            root_dir.display()
        );
        std::process::exit(1);
    }

    let operators = if sync {
        load_operators(&root_dir)
    } else {
        Vec::new()
    };

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        "  CipherVault Background Watcher Agent".bold().green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Vault Root:    {}", root_dir.display());
    println!("  Debounce:      {} seconds", debounce_secs);
    println!(
        "  Auto-sync:     {}",
        if sync {
            "Enabled".green()
        } else {
            "Disabled (local only)".yellow()
        }
    );
    if sync {
        println!("  Operators:     {}", operators.join(", ").dimmed());
    }
    if cli.dry_run {
        println!("  Mode:          {}.", "DRY-RUN (inspect only)".yellow());
    }

    let config = WatcherConfig {
        root_dir,
        debounce: Duration::from_secs(debounce_secs),
        replicate_remote: sync,
        operators,
        dry_run: cli.dry_run,
    };

    let guardian_enabled =
        cli.guardian || std::env::var("CIPHERVAULT_GUARDIAN").as_deref() == Ok("1");
    if guardian_enabled {
        let root = config.root_dir.clone();
        println!(
            "  Guardian:      {} (sprawl scan every 60s)",
            "Enabled".green()
        );
        tokio::spawn(async move {
            let guardian = LocalGuardian::new(&root);
            loop {
                let tracked = ciphervault_local_store::LocalVaultStore::open(
                    root.join(".ciphervault").join("vault.db"),
                )
                .and_then(|s| s.list_tracked_files())
                .map(|files| files.into_iter().map(|(p, _)| p).collect::<Vec<_>>())
                .unwrap_or_default();
                match guardian.scan(&tracked, false) {
                    Ok(report) if !report.clean => {
                        eprintln!(
                            "[guardian] {} secret-sprawl violation(s) in {} scanned file(s)",
                            report.violations_count, report.total_scanned
                        );
                        for v in &report.violations {
                            eprintln!("[guardian] {} {}: {}", v.severity, v.path, v.kind);
                        }
                    }
                    Ok(_) => {}
                    Err(e) => eprintln!("[guardian] scan failed: {e}"),
                }
                tokio::time::sleep(Duration::from_secs(60)).await;
            }
        });
    }

    let watcher = VaultWatcher::new(config)?;

    let (shutdown_tx, shutdown_rx) = tokio::sync::broadcast::channel(1);

    // Graceful Ctrl+C handling
    let tx = shutdown_tx.clone();
    tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            println!("\nReceived Ctrl+C, shutting down agent...");
            let _ = tx.send(());
        }
    });

    watcher.run_loop(shutdown_rx).await?;

    Ok(())
}
