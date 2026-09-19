//! Git hook install and check commands.

use anyhow::{bail, Result};
use colored::Colorize;
use std::fs;
use std::path::Path;

use crate::util::get_vault_store;

pub(crate) fn cmd_hook_install() -> Result<()> {
    let git_dir = Path::new(".git");
    if !git_dir.exists() {
        bail!("No .git directory found. Ensure you are in the root of a Git repository.");
    }
    let hooks_dir = git_dir.join("hooks");
    fs::create_dir_all(&hooks_dir)?;
    let pre_commit_path = hooks_dir.join("pre-commit");

    let script = r#"#!/bin/sh
# CipherVault pre-commit hook: secret leak prevention & modification checks
ciphervault hook check
"#;

    fs::write(&pre_commit_path, script)?;

    println!(
        "{}",
        "✓ Installed CipherVault pre-commit hook into .git/hooks/pre-commit"
            .green()
            .bold()
    );
    println!(
        "CipherVault will now inspect Git staging before every commit to prevent secret leaks."
    );
    Ok(())
}

pub(crate) fn cmd_hook_check() -> Result<()> {
    let store = get_vault_store()?;
    let tracked = store.list_tracked_files()?;

    // 1. Check staged files via git
    let output = std::process::Command::new("git")
        .args(["diff", "--cached", "--name-only"])
        .output();

    if let Ok(out) = output {
        let staged_text = String::from_utf8_lossy(&out.stdout);
        let staged_files: Vec<&str> = staged_text
            .lines()
            .map(|l| l.trim())
            .filter(|l| !l.is_empty())
            .collect();

        for (rel_path, _) in &tracked {
            let path_str = rel_path.to_string_lossy().replace('\\', "/");
            if staged_files.iter().any(|s| *s == path_str) {
                eprintln!();
                eprintln!("{}", "================================================================================".red());
                eprintln!("{}", "        [CRITICAL SECURITY ALERT] CIPHERVAULT SECRET STAGED IN GIT              ".bold().red());
                eprintln!("{}", "================================================================================".red());
                eprintln!(
                    "Tracked confidential file '{}' is currently staged for commit in Git!",
                    path_str.yellow().bold()
                );
                eprintln!(
                    "Plaintext secrets must NEVER be committed to Git version control history."
                );
                eprintln!();
                eprintln!("To unstage this secret immediately, run:");
                eprintln!("  {}", format!("git reset HEAD {}", path_str).cyan().bold());
                eprintln!();
                eprintln!(
                    "CipherVault snapshots protect this file independently without Git tracking."
                );
                eprintln!("{}", "================================================================================".red());
                std::process::exit(1);
            }
        }
    }

    println!("✓ CipherVault pre-commit check: No confidential secrets staged in Git.");
    Ok(())
}
