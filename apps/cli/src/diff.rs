//! Encrypted Secret Comparison & Revision History Engine
//!
//! Provides colorized, shoulder-surfing safe diffs for confidential files
//! comparing working tree files, snapshot revisions, and historical snapshots.

use colored::Colorize;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

/// Type of change detected for a specific secret key or line.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "details")]
pub enum ChangeType {
    Added {
        value: String,
    },
    Removed {
        value: String,
    },
    Modified {
        old_value: String,
        new_value: String,
    },
    Unchanged {
        value: String,
    },
}

/// A diff entry for a single variable key.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SecretDiffEntry {
    pub key: String,
    pub change: ChangeType,
}

/// Complete diff report for a single confidential file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FileDiffReport {
    pub file_path: String,
    pub is_dotenv: bool,
    pub entries: Vec<SecretDiffEntry>,
    pub added_count: usize,
    pub removed_count: usize,
    pub modified_count: usize,
}

/// Full multi-file diff report.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct DiffReport {
    pub old_source: String,
    pub new_source: String,
    pub files: Vec<FileDiffReport>,
    pub total_added: usize,
    pub total_removed: usize,
    pub total_modified: usize,
}

impl DiffReport {
    pub fn new(old_source: String, new_source: String) -> Self {
        Self {
            old_source,
            new_source,
            files: Vec::new(),
            total_added: 0,
            total_removed: 0,
            total_modified: 0,
        }
    }

    pub fn add_file_report(&mut self, report: FileDiffReport) {
        self.total_added += report.added_count;
        self.total_removed += report.removed_count;
        self.total_modified += report.modified_count;
        self.files.push(report);
    }

    pub fn has_changes(&self) -> bool {
        self.total_added > 0 || self.total_removed > 0 || self.total_modified > 0
    }
}

/// Masks a secret value for shoulder-surfing and screen recording protection.
pub fn mask_value(val: &str) -> String {
    let len = val.chars().count();
    if len <= 6 {
        return "***".to_string();
    }
    if len <= 12 {
        let first_two: String = val.chars().take(2).collect();
        let last_two: String = val.chars().skip(len - 2).collect();
        return format!("{}***{}", first_two, last_two);
    }
    let first_three: String = val.chars().take(3).collect();
    let last_three: String = val.chars().skip(len - 3).collect();
    format!("{}***{}", first_three, last_three)
}

/// Computes the diff between two sets of dotenv key-value pairs.
pub fn diff_dotenv(
    file_path: &str,
    old_vars: &[(String, String)],
    new_vars: &[(String, String)],
    reveal: bool,
) -> FileDiffReport {
    let old_map: BTreeMap<&str, &str> = old_vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let new_map: BTreeMap<&str, &str> = new_vars
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();

    let mut all_keys: BTreeSet<&str> = BTreeSet::new();
    for k in old_map.keys() {
        all_keys.insert(k);
    }
    for k in new_map.keys() {
        all_keys.insert(k);
    }

    let mut entries = Vec::new();
    let mut added_count = 0;
    let mut removed_count = 0;
    let mut modified_count = 0;

    for key in all_keys {
        match (old_map.get(key), new_map.get(key)) {
            (None, Some(&new_val)) => {
                added_count += 1;
                let display_val = if reveal {
                    new_val.to_string()
                } else {
                    mask_value(new_val)
                };
                entries.push(SecretDiffEntry {
                    key: key.to_string(),
                    change: ChangeType::Added { value: display_val },
                });
            }
            (Some(&old_val), None) => {
                removed_count += 1;
                let display_val = if reveal {
                    old_val.to_string()
                } else {
                    mask_value(old_val)
                };
                entries.push(SecretDiffEntry {
                    key: key.to_string(),
                    change: ChangeType::Removed { value: display_val },
                });
            }
            (Some(&old_val), Some(&new_val)) => {
                if old_val == new_val {
                    let display_val = if reveal {
                        old_val.to_string()
                    } else {
                        mask_value(old_val)
                    };
                    entries.push(SecretDiffEntry {
                        key: key.to_string(),
                        change: ChangeType::Unchanged { value: display_val },
                    });
                } else {
                    modified_count += 1;
                    let display_old = if reveal {
                        old_val.to_string()
                    } else {
                        mask_value(old_val)
                    };
                    let display_new = if reveal {
                        new_val.to_string()
                    } else {
                        mask_value(new_val)
                    };
                    entries.push(SecretDiffEntry {
                        key: key.to_string(),
                        change: ChangeType::Modified {
                            old_value: display_old,
                            new_value: display_new,
                        },
                    });
                }
            }
            (None, None) => unreachable!(),
        }
    }

    FileDiffReport {
        file_path: file_path.to_string(),
        is_dotenv: true,
        entries,
        added_count,
        removed_count,
        modified_count,
    }
}

/// Computes a line-by-line diff for arbitrary text files.
pub fn diff_text(file_path: &str, old_text: &str, new_text: &str, reveal: bool) -> FileDiffReport {
    let old_lines: Vec<&str> = old_text.lines().collect();
    let new_lines: Vec<&str> = new_text.lines().collect();

    let mut entries = Vec::new();
    let mut added_count = 0;
    let mut removed_count = 0;

    let old_set: BTreeSet<&str> = old_lines.iter().copied().collect();
    let new_set: BTreeSet<&str> = new_lines.iter().copied().collect();

    for line in &old_lines {
        if !new_set.contains(line) {
            removed_count += 1;
            let display_val = if reveal {
                line.to_string()
            } else {
                mask_value(line)
            };
            entries.push(SecretDiffEntry {
                key: "-".to_string(),
                change: ChangeType::Removed { value: display_val },
            });
        }
    }

    for line in &new_lines {
        if !old_set.contains(line) {
            added_count += 1;
            let display_val = if reveal {
                line.to_string()
            } else {
                mask_value(line)
            };
            entries.push(SecretDiffEntry {
                key: "+".to_string(),
                change: ChangeType::Added { value: display_val },
            });
        }
    }

    FileDiffReport {
        file_path: file_path.to_string(),
        is_dotenv: false,
        entries,
        added_count,
        removed_count,
        modified_count: 0,
    }
}

/// Prints a colorized diff report to stdout.
pub fn print_diff_report(report: &DiffReport) {
    println!(
        "{}",
        "=======================================================".cyan()
    );
    println!(
        "  {} ({} -> {})",
        "CipherVault Encrypted Revision Diff".bold().green(),
        report.old_source.yellow(),
        report.new_source.yellow()
    );
    println!(
        "{}",
        "=======================================================".cyan()
    );

    if !report.has_changes() {
        println!("{}", "✓ No changes detected. Files are identical.".green());
        return;
    }

    for file in &report.files {
        if file.added_count == 0 && file.removed_count == 0 && file.modified_count == 0 {
            continue;
        }

        println!();
        println!(
            "{} {} ({} added, {} modified, {} removed)",
            "diff".bold().magenta(),
            file.file_path.bold().white(),
            file.added_count.to_string().green(),
            file.modified_count.to_string().yellow(),
            file.removed_count.to_string().red()
        );
        println!("--- old/{}", file.file_path);
        println!("+++ new/{}", file.file_path);

        if file.is_dotenv {
            for entry in &file.entries {
                match &entry.change {
                    ChangeType::Added { value } => {
                        println!(
                            "  {} {} = {}",
                            "+".bold().green(),
                            entry.key.green(),
                            value.green()
                        );
                    }
                    ChangeType::Removed { value } => {
                        println!(
                            "  {} {} = {}",
                            "-".bold().red(),
                            entry.key.red(),
                            value.red()
                        );
                    }
                    ChangeType::Modified {
                        old_value,
                        new_value,
                    } => {
                        println!(
                            "  {} {}: {} -> {}",
                            "~".bold().yellow(),
                            entry.key.yellow(),
                            old_value.red(),
                            new_value.green()
                        );
                    }
                    ChangeType::Unchanged { .. } => {
                        // Skip printing unchanged variables to keep terminal diff compact
                    }
                }
            }
        } else {
            for entry in &file.entries {
                match &entry.change {
                    ChangeType::Added { value } => {
                        println!("  {} {}", "+".bold().green(), value.green());
                    }
                    ChangeType::Removed { value } => {
                        println!("  {} {}", "-".bold().red(), value.red());
                    }
                    _ => {}
                }
            }
        }
    }

    println!();
    println!(
        "Summary: {} addition(s), {} modification(s), {} removal(s) across {} file(s)",
        report.total_added.to_string().green(),
        report.total_modified.to_string().yellow(),
        report.total_removed.to_string().red(),
        report.files.len()
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("short"), "***");
        assert_eq!(mask_value("12345678"), "12***78");
        assert_eq!(mask_value("sk_test_51MzQ4xyz999"), "sk_***999");
    }

    #[test]
    fn test_diff_dotenv_add_modify_remove() {
        let old_vars = vec![
            ("DATABASE_URL".into(), "postgres://old_db".into()),
            ("REMOVED_KEY".into(), "old_secret".into()),
            ("UNCHANGED_KEY".into(), "same_val".into()),
        ];
        let new_vars = vec![
            ("DATABASE_URL".into(), "postgres://new_db".into()),
            ("ADDED_KEY".into(), "new_secret".into()),
            ("UNCHANGED_KEY".into(), "same_val".into()),
        ];

        let report = diff_dotenv(".env", &old_vars, &new_vars, true);
        assert_eq!(report.added_count, 1);
        assert_eq!(report.removed_count, 1);
        assert_eq!(report.modified_count, 1);

        let added = report
            .entries
            .iter()
            .find(|e| e.key == "ADDED_KEY")
            .unwrap();
        assert_eq!(
            added.change,
            ChangeType::Added {
                value: "new_secret".into()
            }
        );

        let removed = report
            .entries
            .iter()
            .find(|e| e.key == "REMOVED_KEY")
            .unwrap();
        assert_eq!(
            removed.change,
            ChangeType::Removed {
                value: "old_secret".into()
            }
        );

        let modified = report
            .entries
            .iter()
            .find(|e| e.key == "DATABASE_URL")
            .unwrap();
        assert_eq!(
            modified.change,
            ChangeType::Modified {
                old_value: "postgres://old_db".into(),
                new_value: "postgres://new_db".into(),
            }
        );
    }

    #[test]
    fn test_diff_masking() {
        let old_vars = vec![("SECRET".into(), "sk_live_1234567890abcdef".into())];
        let new_vars = vec![("SECRET".into(), "sk_live_0987654321fedcba".into())];

        let masked_report = diff_dotenv(".env", &old_vars, &new_vars, false);
        let entry = &masked_report.entries[0];
        match &entry.change {
            ChangeType::Modified {
                old_value,
                new_value,
            } => {
                assert!(old_value.contains("***"));
                assert!(new_value.contains("***"));
                assert!(!old_value.contains("1234567890"));
            }
            _ => panic!("Expected modified change"),
        }
    }
}
