//! Git hook install and secret leak prevention check commands.

use anyhow::{bail, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

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
ciphervault hook check --deep
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

/// Identifies if a relative filename looks like a confidential credential file.
fn is_suspicious_secret_file(path_str: &str) -> bool {
    let lower = path_str.to_ascii_lowercase();
    let name = Path::new(&lower)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");

    // .env variants (.env, .env.local, .env.production, .env.staging, .env.backup)
    if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
        return true;
    }

    // Common private key & certificate files
    if name.ends_with(".key")
        || name.ends_with(".pem")
        || name.ends_with(".pkcs12")
        || name.ends_with(".pfx")
        || name.ends_with(".keystore")
    {
        return true;
    }

    // Common SSH & cloud service account credentials
    if name == "id_rsa"
        || name == "id_ed25519"
        || name == "id_ecdsa"
        || name.starts_with("service_account")
        || name.starts_with("service-account")
        || name == "credentials.json"
        || name == "secrets.json"
    {
        return true;
    }

    false
}

#[derive(serde::Serialize)]
struct HookViolation {
    kind: String,
    path: String,
    details: String,
    remediation: String,
}

pub(crate) fn cmd_hook_check(deep: bool, fix: bool, json: bool) -> Result<()> {
    let store_res = get_vault_store();
    let tracked: Vec<(PathBuf, [u8; 32])> = store_res
        .as_ref()
        .ok()
        .and_then(|store| store.list_tracked_files().ok())
        .unwrap_or_default();

    let mut violations: Vec<HookViolation> = Vec::new();
    let mut fixed_files: Vec<String> = Vec::new();

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

        // 1a. Check for tracked vault files staged in git
        for (rel_path, _) in &tracked {
            let path_str = rel_path.to_string_lossy().replace('\\', "/");
            if staged_files.iter().any(|s| *s == path_str) {
                violations.push(HookViolation {
                    kind: "STAGED_TRACKED_SECRET".to_string(),
                    path: path_str.clone(),
                    details: "Tracked confidential file is currently staged for commit in Git."
                        .to_string(),
                    remediation: format!("git reset HEAD {path_str}"),
                });
            }
        }

        // 1b. Check for suspicious untracked secret files staged in git
        for staged in &staged_files {
            if is_suspicious_secret_file(staged) {
                let is_tracked = tracked
                    .iter()
                    .any(|(p, _)| p.to_string_lossy().replace('\\', "/") == *staged);
                if !is_tracked {
                    violations.push(HookViolation {
                        kind: "STAGED_UNTRACKED_SECRET_FILE".to_string(),
                        path: staged.to_string(),
                        details: "File matches confidential secret file pattern but is staged in Git without CipherVault protection.".to_string(),
                        remediation: format!("git reset HEAD {staged} && ciphervault track {staged}"),
                    });
                }
            }
        }
    }

    // 2. Deep scan: Inspect staged diff contents for leaked secret shapes
    if deep {
        let diff_output = std::process::Command::new("git")
            .args(["diff", "--cached", "-U0"])
            .output();

        if let Ok(diff_out) = diff_output {
            let diff_text = String::from_utf8_lossy(&diff_out.stdout);
            let mut current_file = String::new();

            for line in diff_text.lines() {
                if let Some(path) = line.strip_prefix("+++ b/") {
                    current_file = path.trim().to_string();
                } else if line.starts_with('+') && !line.starts_with("+++") {
                    let content = &line[1..];
                    if ciphervault_redact::contains_secret_shaped(content) {
                        violations.push(HookViolation {
                            kind: "STAGED_SECRET_PATTERN_DETECTED".to_string(),
                            path: current_file.clone(),
                            details: "Staged diff contains credential-shaped token, private key, or password assignment.".to_string(),
                            remediation: format!("Review and unstage sensitive content from {current_file}"),
                        });
                        break;
                    }
                }
            }
        }

        // 3. Workspace sprawl detection: check for unignored .env files
        if let Ok(entries) = std::fs::read_dir(".") {
            let gitignore_path = Path::new(".gitignore");
            let gitignore_content = if gitignore_path.exists() {
                std::fs::read_to_string(gitignore_path).unwrap_or_default()
            } else {
                String::new()
            };

            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if is_suspicious_secret_file(&name) {
                    let is_tracked = tracked.iter().any(|(p, _)| p.to_string_lossy() == name);
                    let is_in_gitignore = gitignore_content.lines().any(|l| {
                        l.trim() == name || l.trim() == format!("/{name}") || l.trim() == ".env*"
                    });

                    if !is_tracked && !is_in_gitignore {
                        if fix {
                            // Automatically append to .gitignore
                            use std::io::Write;
                            if let Ok(mut f) = fs::OpenOptions::new()
                                .create(true)
                                .append(true)
                                .open(gitignore_path)
                            {
                                let _ = writeln!(f, "{name}");
                                fixed_files.push(name.clone());
                            }
                        } else {
                            violations.push(HookViolation {
                                kind: "UNPROTECTED_SECRET_SPRAWL".to_string(),
                                path: name.clone(),
                                details: format!("Confidential file '{name}' is not in .gitignore and not tracked by CipherVault."),
                                remediation: format!("Add '{name}' to .gitignore or run `ciphervault track {name}` (or pass --fix to auto-ignore)"),
                            });
                        }
                    }
                }
            }
        }
    }

    if json {
        let report = serde_json::json!({
            "status": if violations.is_empty() { "clean" } else { "violations_found" },
            "violations_count": violations.len(),
            "violations": violations,
            "fixed_files": fixed_files,
            "deep_scan": deep,
        });
        println!("{}", serde_json::to_string_pretty(&report)?);
        if !violations.is_empty() {
            std::process::exit(1);
        }
        return Ok(());
    }

    if !violations.is_empty() {
        eprintln!();
        eprintln!(
            "{}",
            "================================================================================"
                .red()
        );
        eprintln!(
            "{}",
            "        [CRITICAL SECURITY ALERT] CIPHERVAULT SECRET LEAK DETECTED              "
                .bold()
                .red()
        );
        eprintln!(
            "{}",
            "================================================================================"
                .red()
        );
        for v in &violations {
            eprintln!(
                "  • [{}] {} : {}",
                v.kind.bold().yellow(),
                v.path.cyan().bold(),
                v.details
            );
            eprintln!("    Remediation: {}", v.remediation.green());
            eprintln!();
        }
        eprintln!("Plaintext secrets must NEVER be committed to Git version control history.");
        eprintln!(
            "{}",
            "================================================================================"
                .red()
        );
        std::process::exit(1);
    }

    if !fixed_files.is_empty() {
        println!(
            "{}",
            format!(
                "✓ Automatically added {} file(s) to .gitignore: {}",
                fixed_files.len(),
                fixed_files.join(", ")
            )
            .green()
        );
    }

    println!("✓ CipherVault pre-commit check: No confidential secrets staged in Git.");
    Ok(())
}
