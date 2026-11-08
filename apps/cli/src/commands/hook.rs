//! Git hook install and secret leak prevention check commands.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::{Path, PathBuf};

use crate::util::get_vault_store;

pub(crate) fn cmd_hook_install(force: bool) -> Result<()> {
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

    // U-H7: never silently clobber an existing hook chain. Back ours up
    // when replacing only with explicit consent.
    if pre_commit_path.exists() {
        let existing = fs::read_to_string(&pre_commit_path).unwrap_or_default();
        if !existing.contains("ciphervault hook check") {
            if !force {
                bail!(
                    "'.git/hooks/pre-commit' already exists and is not ours. Re-run with 'hook install --force' to replace it (the current file is backed up to '.git/hooks/pre-commit.ciphervault.bak'), or chain manually by appending 'ciphervault hook check --deep' to your hook."
                );
            }
            let backup = hooks_dir.join("pre-commit.ciphervault.bak");
            fs::write(&backup, &existing)
                .with_context(|| format!("backing up existing hook to '{}'", backup.display()))?;
            println!(
                "{}",
                format!(
                    "Backed up existing pre-commit hook to '{}'",
                    backup.display()
                )
                .yellow()
            );
        }
    }

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

/// Minimal `*`-only glob match for gitignore-style patterns (no crates).
fn glob_match(pattern: &str, text: &str) -> bool {
    let (px, tx) = (pattern.as_bytes(), text.as_bytes());
    let (mut pi, mut ti) = (0usize, 0usize);
    let (mut star_at, mut back_at): (Option<usize>, usize) = (None, 0);
    while ti < tx.len() {
        if pi < px.len() && px[pi] == b'*' {
            star_at = Some(pi);
            pi += 1;
            back_at = ti;
        } else if pi < px.len() && px[pi] == tx[ti] {
            pi += 1;
            ti += 1;
        } else if let Some(s) = star_at {
            pi = s + 1;
            back_at += 1;
            ti = back_at;
        } else {
            return false;
        }
    }
    while pi < px.len() && px[pi] == b'*' {
        pi += 1;
    }
    pi == px.len()
}

/// Returns true when a `.gitignore` text leaves `rel_norm` ignored OR
/// explicitly re-included. Git semantics for ignores: the LAST matching
/// positive pattern wins; but any matching `!` negation counts as covered
/// regardless of order — a negation is always an explicit user decision
/// to track the file, and the hook must not veto explicit intent or nag
/// on every commit (it still won't be proposed by secret import).
fn gitignore_covers(content: &str, rel_norm: &str, name: &str) -> bool {
    let mut ignored = false;
    let mut negated = false;
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let (pattern, is_neg) = match trimmed.strip_prefix('!') {
            Some(rest) => (rest.trim_start_matches('/'), true),
            None => (trimmed.trim_start_matches('/'), false),
        };
        let matched = pattern == name
            || pattern == rel_norm
            || (pattern.ends_with('/') && rel_norm.starts_with(pattern))
            || (pattern.contains('*')
                && (glob_match(pattern, name)
                    || glob_match(pattern, rel_norm)
                    || glob_match(pattern.trim_start_matches("**/"), name)));
        if matched {
            if is_neg {
                negated = true;
            } else {
                ignored = true;
            }
        }
    }
    ignored || negated
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

        // 3. Workspace sprawl detection: recursive walk for unignored secret
        // files. Honors exact, /-prefixed, *-wildcard, and dir-prefix
        // gitignore rules (negations excluded — re-included example files
        // must never be flagged).
        let gitignore_path = Path::new(".gitignore");
        let gitignore_content = if gitignore_path.exists() {
            std::fs::read_to_string(gitignore_path).unwrap_or_default()
        } else {
            String::new()
        };
        for entry in walkdir::WalkDir::new(".")
            .max_depth(6)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if entry.file_type().is_dir() {
                continue;
            }
            let rel_norm = entry
                .path()
                .to_string_lossy()
                .replace('\\', "/")
                .trim_start_matches("./")
                .to_string();
            if rel_norm.starts_with(".git/")
                || rel_norm.starts_with("target/")
                || rel_norm.starts_with("node_modules/")
                || rel_norm.starts_with(".ciphervault/")
            {
                continue;
            }
            let name = entry.file_name().to_string_lossy().to_string();
            if is_suspicious_secret_file(&name) {
                let is_tracked = tracked.iter().any(|(p, _)| p.to_string_lossy() == rel_norm);
                if !is_tracked && !gitignore_covers(&gitignore_content, &rel_norm, &name) {
                    if fix {
                        // Automatically append to .gitignore
                        use std::io::Write;
                        if let Ok(mut f) = fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(gitignore_path)
                        {
                            let _ = writeln!(f, "{rel_norm}");
                            fixed_files.push(rel_norm.clone());
                        }
                    } else {
                        violations.push(HookViolation {
                            kind: "UNPROTECTED_SECRET_SPRAWL".to_string(),
                            path: rel_norm.clone(),
                            details: format!("Confidential file '{rel_norm}' is not in .gitignore and not tracked by CipherVault."),
                            remediation: format!("Add '{rel_norm}' to .gitignore or run `ciphervault track {rel_norm}` (or pass --fix to auto-ignore)"),
                        });
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

#[cfg(test)]
mod hook_tests {
    use super::*;

    #[test]
    fn glob_match_star_forms() {
        assert!(glob_match("*.env", ".env"));
        assert!(glob_match("*.env", "prod.env"));
        assert!(!glob_match("*.env", ".env.example.bak"));
        assert!(glob_match(".env*", ".env.production"));
        assert!(!glob_match("*.key", "monkey"));
        assert!(glob_match("*", "anything"));
    }

    #[test]
    fn gitignore_covers_last_match_wins() {
        // Exact + slash-prefixed.
        assert!(gitignore_covers(".env\n", ".env", ".env"));
        assert!(gitignore_covers(
            "/sub/nested.env\n",
            "sub/nested.env",
            "nested.env"
        ));
        // Wildcards.
        assert!(gitignore_covers("*.key\n", "sub/nested.key", "nested.key"));
        assert!(gitignore_covers("**/.env\n", "sub/.env", ".env"));
        assert!(!gitignore_covers(
            "**/.env\n",
            "sub/nested.env",
            "nested.env"
        ));
        // Dir prefix.
        assert!(gitignore_covers("secrets/\n", "secrets/a.env", "a.env"));
        // Negation = explicit user decision to track: never flag, even
        // when it cancels an earlier ignore.
        assert!(gitignore_covers(
            "*.env\n!keep.env\n",
            "keep.env",
            "keep.env"
        ));
        // A later positive rule re-ignores only when no negation matches
        // the same file... a negation anywhere in the file still wins,
        // because it proves explicit intent.
        assert!(gitignore_covers(
            "*.env\n!keep.env\nkeep.env\n",
            "keep.env",
            "keep.env"
        ));
        // Comments and blanks never match.
        assert!(!gitignore_covers("# *.env\n\n", "a.env", "a.env"));
    }
}
