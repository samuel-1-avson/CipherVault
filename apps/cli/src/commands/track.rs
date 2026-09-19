//! Track and untrack commands.

use anyhow::{bail, Result};
use colored::Colorize;
use std::path::{Path, PathBuf};

use crate::util::{ensure_file_in_gitignore, get_vault_store, scan_gitignore_for_secrets};

pub(crate) fn cmd_track(
    mut paths: Vec<PathBuf>,
    from_gitignore: bool,
    no_gitignore: bool,
) -> Result<()> {
    let store = get_vault_store()?;

    if from_gitignore {
        let discovered = scan_gitignore_for_secrets(Path::new("."))?;
        if discovered.is_empty() {
            println!(
                "{}",
                "No confidential secret files discovered in .gitignore.".yellow()
            );
        } else {
            println!(
                "{} Discovered {} secret file(s) in .gitignore.",
                "[GITIGNORE]".bold().cyan(),
                discovered.len()
            );
            for p in discovered {
                if !paths.contains(&p) {
                    paths.push(p);
                }
            }
        }
    }

    if paths.is_empty() {
        bail!(
            "No files specified to track.\nProvide paths (e.g. 'ciphervault track .env') or use 'ciphervault track --from-gitignore'."
        );
    }

    println!("{}", "Tracking confidential files:".bold());

    for path in paths {
        let path_str = path.to_string_lossy();
        let file_id = store.track_file(&path_str)?;
        let exists = path.exists();
        let status_str = if exists {
            "[found]".green()
        } else {
            "[planned (not on disk yet)]".yellow()
        };
        println!(
            "  {} {} {} (ID: {})",
            "+".green(),
            path_str,
            status_str,
            hex::encode(&file_id[0..4]).dimmed()
        );

        if !no_gitignore {
            if let Ok(added) = ensure_file_in_gitignore(&path) {
                if added {
                    println!(
                        "    ↳ {}",
                        format!(
                            "Appended '{}' to .gitignore to prevent accidental git leaks",
                            path_str
                        )
                        .dimmed()
                    );
                }
            }
        }
    }

    println!(
        "\nTracked files registered. Run '{}' to capture and replicate an encrypted snapshot.",
        "ciphervault push".cyan()
    );
    Ok(())
}

pub(crate) fn cmd_untrack(paths: Vec<PathBuf>) -> Result<()> {
    let store = get_vault_store()?;
    println!("{}", "Untracking confidential files:".bold());

    for path in paths {
        let path_str = path.to_string_lossy();
        let removed = store.untrack_file(&path_str)?;
        if removed {
            println!("  {} {} {}", "-".red(), path_str, "[untracked]".yellow());
        } else {
            println!(
                "  {} {} {}",
                "!".dimmed(),
                path_str,
                "[not currently tracked]".dimmed()
            );
        }
    }
    Ok(())
}
