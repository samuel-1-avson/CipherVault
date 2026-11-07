//! Local AI Guardian: continuous runtime secret sprawl & credential leak scanner.
//!
//! Inspects the local workspace to proactively detect newly created secret files,
//! untracked `.env*` variants, private keys, and credential-shaped tokens
//! before they can be committed to version control or leaked into agent prompts.

use anyhow::Result;
use ciphervault_redact::contains_secret_shaped;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GuardianViolation {
    pub kind: String,
    pub path: String,
    pub details: String,
    pub severity: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardianReport {
    pub clean: bool,
    pub total_scanned: usize,
    pub violations_count: usize,
    pub violations: Vec<GuardianViolation>,
    pub auto_fixed: Vec<String>,
}

pub struct LocalGuardian {
    root_dir: PathBuf,
    max_file_size_bytes: u64,
}

impl LocalGuardian {
    pub fn new(root_dir: impl AsRef<Path>) -> Self {
        Self {
            root_dir: root_dir.as_ref().to_path_buf(),
            max_file_size_bytes: 512 * 1024, // 512 KB scan ceiling for secret content
        }
    }

    /// Determines if a file path is a typical confidential credential filename.
    pub fn is_confidential_filename(path: &Path) -> bool {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_ascii_lowercase();

        if name == ".env" || name.starts_with(".env.") || name.ends_with(".env") {
            return true;
        }

        if name.ends_with(".key")
            || name.ends_with(".pem")
            || name.ends_with(".pkcs12")
            || name.ends_with(".pfx")
            || name.ends_with(".keystore")
        {
            return true;
        }

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

    /// Scans the workspace directory for secret sprawl.
    pub fn scan(&self, tracked_paths: &[PathBuf], auto_fix: bool) -> Result<GuardianReport> {
        let mut violations = Vec::new();
        let mut auto_fixed = Vec::new();
        let mut scanned_count = 0;

        let gitignore_path = self.root_dir.join(".gitignore");
        let gitignore_content = if gitignore_path.exists() {
            fs::read_to_string(&gitignore_path).unwrap_or_default()
        } else {
            String::new()
        };

        for entry in WalkDir::new(&self.root_dir)
            .into_iter()
            .filter_entry(|e| {
                let name = e.file_name().to_string_lossy();
                // Exclude internal metadata directories
                name != ".git"
                    && name != ".ciphervault"
                    && name != "target"
                    && name != "node_modules"
                    && name != "dist"
                    && name != ".gemini"
            })
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }

            scanned_count += 1;
            let full_path = entry.path();
            let Ok(rel_path) = full_path.strip_prefix(&self.root_dir) else {
                continue;
            };
            let rel_str = rel_path.to_string_lossy().replace('\\', "/");

            let is_tracked = tracked_paths
                .iter()
                .any(|t| t.to_string_lossy().replace('\\', "/") == rel_str);

            let is_ignored = gitignore_content
                .lines()
                .any(|l| l.trim() == rel_str || l.trim() == format!("/{rel_str}"));

            // 1. Filename credential pattern check
            if Self::is_confidential_filename(rel_path) {
                if !is_tracked && !is_ignored {
                    violations.push(GuardianViolation {
                        kind: "UNTRACKED_SECRET_SPRAWL".to_string(),
                        path: rel_str.clone(),
                        details: format!("Discovered untracked credential file '{rel_str}' not protected by Git ignore."),
                        severity: "HIGH".to_string(),
                    });

                    if auto_fix {
                        let to_append =
                            if gitignore_content.ends_with('\n') || gitignore_content.is_empty() {
                                format!("{rel_str}\n")
                            } else {
                                format!("\n{rel_str}\n")
                            };
                        let mut f = fs::OpenOptions::new()
                            .create(true)
                            .append(true)
                            .open(&gitignore_path)?;
                        use std::io::Write;
                        f.write_all(to_append.as_bytes())?;
                        auto_fixed.push(rel_str.clone());
                    }
                }
            } else if !is_ignored && !is_tracked {
                // 2. Content credential shape check for small files
                if let Ok(meta) = entry.metadata() {
                    if meta.len() > 0 && meta.len() <= self.max_file_size_bytes {
                        if let Ok(content) = fs::read_to_string(full_path) {
                            if contains_secret_shaped(&content) {
                                violations.push(GuardianViolation {
                                    kind: "SECRET_PATTERN_EXPOSURE".to_string(),
                                    path: rel_str.clone(),
                                    details: format!("File '{rel_str}' contains credential-shaped tokens (scope tokens, bearer headers, or private keys)."),
                                    severity: "CRITICAL".to_string(),
                                });
                            }
                        }
                    }
                }
            }
        }

        let clean = violations.is_empty();
        Ok(GuardianReport {
            clean,
            total_scanned: scanned_count,
            violations_count: violations.len(),
            violations,
            auto_fixed,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_guardian_detects_untracked_secret_file() {
        let temp_dir = std::env::temp_dir().join(format!(
            "cv_guard_test_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let guardian = LocalGuardian::new(&temp_dir);

        // Create an untracked sprawl file
        fs::write(temp_dir.join(".env.local"), "SECRET_KEY=12345\n").unwrap();

        let report = guardian.scan(&[], false).unwrap();
        assert!(!report.clean);
        assert_eq!(report.violations_count, 1);
        assert_eq!(report.violations[0].kind, "UNTRACKED_SECRET_SPRAWL");
        assert_eq!(report.violations[0].path, ".env.local");

        // Test auto_fix
        let fix_report = guardian.scan(&[], true).unwrap();
        assert!(fix_report.auto_fixed.contains(&".env.local".to_string()));
        assert!(temp_dir.join(".gitignore").exists());
        let gi_content = fs::read_to_string(temp_dir.join(".gitignore")).unwrap();
        assert!(gi_content.contains(".env.local"));

        // Subsequent scan now clean because it is ignored
        let clean_report = guardian.scan(&[], false).unwrap();
        assert!(clean_report.clean);

        let _ = fs::remove_dir_all(temp_dir);
    }

    #[test]
    fn test_guardian_detects_secret_shaped_content() {
        let temp_dir = std::env::temp_dir().join(format!(
            "cv_guard_content_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir_all(&temp_dir).unwrap();

        let guardian = LocalGuardian::new(&temp_dir);

        // Regular filename, but containing leaked scope token
        fs::write(
            temp_dir.join("config.json"),
            r#"{"api_key": "cvst1.eyJhbGciOiJFZDI1NTE5In0.secret_token_123"}"#,
        )
        .unwrap();

        let report = guardian.scan(&[], false).unwrap();
        assert!(!report.clean);
        assert_eq!(report.violations_count, 1);
        assert_eq!(report.violations[0].kind, "SECRET_PATTERN_EXPOSURE");

        let _ = fs::remove_dir_all(temp_dir);
    }
}
