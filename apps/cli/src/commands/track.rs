//! Track and untrack commands.

use anyhow::{bail, Result};
use colored::Colorize;
use std::path::PathBuf;

use crate::util::{
    ensure_file_in_gitignore, get_vault_store, remove_file_from_gitignore, scan_gitignore_for_secrets,
};

pub(crate) fn cmd_track(
    mut paths: Vec<PathBuf>,
    from_gitignore: bool,
    no_gitignore: bool,
    allow_planned: bool,
) -> Result<()> {
    let store = get_vault_store()?;
    let root = crate::util::get_workspace_root()?;

    if from_gitignore {
        let (discovered, files_walked) = scan_gitignore_for_secrets(&root)?;
        println!(
            "{}",
            format!("Scanned .gitignore across {files_walked} files (depth ≤ 4).").dimmed()
        );
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
        let exists = root.join(&path).exists();
        // U-H2: a typo'd path used to become a "[planned]" tombstone that
        // push then "backs up" as nothing. Missing paths need --allow-planned.
        if !exists && !allow_planned {
            bail!(
                "cannot track '{}': no such file. Pass --allow-planned to register it anyway (it will back up nothing until it exists).",
                path_str
            );
        }
        let file_id = store.track_file(&path_str)?;
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
        "\nTracked files registered. {}",
        "WARNING: files are NOT durable until 'ciphervault push' succeeds — git now ignores them and operators don't have them yet."
            .yellow()
            .bold()
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
            // U-H10: don't leave the file git-invisible AND un-backed-up.
            // Only the exact line `track` appends is removed; broader rules
            // stay untouched and are reported as such.
            match remove_file_from_gitignore(&path) {
                Ok(true) => println!(
                    "    ↳ {}",
                    format!("Removed '{path_str}' from .gitignore — git sees it again",).dimmed()
                ),
                Ok(false) => println!(
                    "    ↳ {}",
                    "Left .gitignore untouched (no exact entry for this path; check wildcards)".dimmed()
                ),
                Err(error) => println!(
                    "    ↳ {}",
                    format!("Could not clean .gitignore: {error:#}").yellow()
                ),
            }
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
