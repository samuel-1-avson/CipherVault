//! Dashboard server bring-up for the `ui` command.

use crate::{
    open_browser, parse_ui_host, spawn_public_operator_collector, ui_browser_url, ui_router,
    UiServerMode,
};
use anyhow::{bail, Result};
use colored::Colorize;

pub(crate) async fn cmd_ui(
    host: String,
    port: u16,
    no_browser: bool,
    local: bool,
    serve: bool,
    cloud_url: String,
) -> Result<()> {
    if !local && !serve {
        let target_url = cloud_url.trim_end_matches('/').to_string();

        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "{}",
            "  CipherVault Cloud Dashboard & Visual Secrets Explorer"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("  Dashboard URL:  {}", target_url.bold().yellow());
        println!("  Cluster Status: Open the explorer for live operator status");
        println!("  Explorer Scope: Public cluster telemetry and published checkpoints only");
        println!("  Private Vault:  Pass '--local' to open this machine's private workspace.\n");

        if !no_browser {
            println!("Opening {} in default web browser...", target_url.cyan());
            open_browser(&target_url);
        }
        return Ok(());
    }

    let mode = if local {
        UiServerMode::LocalPrivate
    } else {
        UiServerMode::PublicExplorer
    };
    let host_ip = parse_ui_host(&host)?;
    if mode == UiServerMode::LocalPrivate && !host_ip.is_loopback() {
        bail!(
            "Refusing to expose the private local dashboard on {}. Use a loopback address such as 127.0.0.1 or ::1, or use '--serve' for the public read-only explorer.",
            host_ip
        );
    }

    let app = ui_router(mode);
    if mode == UiServerMode::PublicExplorer {
        spawn_public_operator_collector();
    }
    let addr = std::net::SocketAddr::new(host_ip, port);
    let listener = tokio::net::TcpListener::bind(addr).await?;
    let browser_url = ui_browser_url(host_ip, port);

    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "{}",
        match mode {
            UiServerMode::LocalPrivate => {
                "  CipherVault Local Web Dashboard & Vault Inspector"
            }
            UiServerMode::PublicExplorer => "  CipherVault Public Cluster Explorer",
        }
        .bold()
        .green()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!("  Dashboard URL:  {}", browser_url.bold().yellow());
    match mode {
        UiServerMode::LocalPrivate => {
            println!("  Serving Mode:   Private local workspace (loopback only)");
            println!("  Private APIs:   Enabled for this local process");
        }
        UiServerMode::PublicExplorer => {
            println!("  Serving Mode:   Public read-only explorer");
            println!("  Private APIs:   Disabled (use 'ciphervault ui --local' on the vault host)");
        }
    }
    println!("  Press Ctrl+C to stop server.\n");

    if !no_browser {
        let local_url = browser_url;
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_millis(400)).await;
            open_browser(&local_url);
        });
    }

    axum::serve(listener, app).await?;
    Ok(())
}
