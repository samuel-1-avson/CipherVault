//! Encrypted Secret Comparison & Revision History Engine
//!
//! Provides colorized, shoulder-surfing safe diffs for confidential files
//! comparing working tree files, snapshot revisions, and historical snapshots.

use colored::Colorize;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context, Result};
use std::fs;

use ciphervault_format::{from_canonical_cbor, SnapshotManifest};
use ciphervault_snapshot::decrypt_snapshot;

use crate::dotenv;
use crate::util::get_vault_store;
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

/// Diffs one file's raw bytes, routing dotenv files through the masked
/// variable diff. Unparseable dotenv content (e.g. UTF-16) falls back to a
/// lossy text diff so changes are never silently reported as identical.
pub fn diff_file_bytes(
    path: &str,
    old_bytes: &[u8],
    new_bytes: &[u8],
    reveal: bool,
) -> FileDiffReport {
    let name = path.rsplit('/').next().unwrap_or(path);
    let is_dotenv_file = name == ".env" || name.starts_with(".env.") || name.ends_with(".env");
    if is_dotenv_file {
        if let (Ok(old_vars), Ok(new_vars)) = (
            dotenv::parse_dotenv_bytes(old_bytes),
            dotenv::parse_dotenv_bytes(new_bytes),
        ) {
            return diff_dotenv(path, &old_vars, &new_vars, reveal);
        }
    }
    let old_str = String::from_utf8_lossy(old_bytes);
    let new_str = String::from_utf8_lossy(new_bytes);
    diff_text(path, &old_str, &new_str, reveal)
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

pub fn generate_diff_report(
    snapshot_a_opt: Option<String>,
    snapshot_b_opt: Option<String>,
    file_filter_opt: Option<String>,
    reveal: bool,
) -> Result<DiffReport> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

    // Helper to decrypt snapshot files into a map of (relative_path -> Vec<u8>)
    let decrypt_snap = |snap_id: &[u8; 32]| -> Result<std::collections::BTreeMap<String, Vec<u8>>> {
        let (record, encrypted_manifest) = store.get_snapshot(snap_id)?;
        let manifest_key = epoch_key.derive_manifest_key(record.epoch)?;
        let aad = [
            b"CipherVault-Manifest:",
            vault_id.as_slice(),
            &record.epoch.to_le_bytes(),
        ]
        .concat();
        let manifest_bytes =
            ciphervault_crypto::decrypt_chunk(&manifest_key, &encrypted_manifest, &aad)?;
        let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

        let mut needed_cids = Vec::new();
        for file in &manifest.files {
            for cid_bytes in &file.chunk_cids {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(cid_bytes);
                needed_cids.push(arr);
            }
        }
        let chunks = store.get_chunks(&needed_cids)?;
        let files = decrypt_snapshot(
            &vault_id,
            &epoch_key,
            record.epoch,
            &encrypted_manifest,
            &chunks,
        )?;

        let mut map = std::collections::BTreeMap::new();
        for f in files {
            map.insert(f.relative_path.replace('\\', "/"), f.plaintext);
        }
        Ok(map)
    };

    let parse_snap_id = |s: &str| -> Result<[u8; 32]> {
        let bytes = hex::decode(s.trim())?;
        if bytes.len() != 32 {
            bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
        }
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        Ok(arr)
    };

    let read_working_tree = || -> std::collections::BTreeMap<String, Vec<u8>> {
        let mut map = std::collections::BTreeMap::new();
        if let Ok(tracked) = store.list_tracked_files() {
            for (p, _) in tracked {
                let rel_str = p.display().to_string().replace('\\', "/");
                if p.exists() {
                    if let Ok(data) = fs::read(&p) {
                        map.insert(rel_str, data);
                    }
                }
            }
        }
        map
    };

    let get_head_cid = || -> Result<[u8; 32]> {
        let head = store.get_active_head()?.context(
            "Vault has no snapshots committed yet. Create a snapshot first with 'ciphervault push'",
        )?;
        if head.snapshot_id.len() != 32 {
            bail!("Invalid snapshot ID length in active head");
        }
        let mut head_cid = [0u8; 32];
        head_cid.copy_from_slice(&head.snapshot_id);
        Ok(head_cid)
    };

    let snap_a_clean = snapshot_a_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let snap_b_clean = snapshot_b_opt
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let (old_label, new_label, old_files, new_files) =
        match (snap_a_clean.as_deref(), snap_b_clean.as_deref()) {
            (None, None)
            | (Some("head"), None)
            | (Some("head"), Some("working"))
            | (None, Some("working")) => {
                let head_cid = get_head_cid()?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = read_working_tree();
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    "working tree".to_string(),
                    old_map,
                    new_map,
                )
            }
            (Some("working"), Some("head")) => {
                let head_cid = get_head_cid()?;
                let old_map = read_working_tree();
                let new_map = decrypt_snap(&head_cid)?;
                (
                    "working tree".to_string(),
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), None) | (Some(a_str), Some("working")) => {
                let a_id = parse_snap_id(a_str)?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = read_working_tree();
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    "working tree".to_string(),
                    old_map,
                    new_map,
                )
            }
            (Some("working"), Some(b_str)) => {
                let b_id = parse_snap_id(b_str)?;
                let old_map = read_working_tree();
                let new_map = decrypt_snap(&b_id)?;
                (
                    "working tree".to_string(),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some("head"), Some(b_str)) => {
                let head_cid = get_head_cid()?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), Some("head")) => {
                let a_id = parse_snap_id(a_str)?;
                let head_cid = get_head_cid()?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = decrypt_snap(&head_cid)?;
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    old_map,
                    new_map,
                )
            }
            (Some(a_str), Some(b_str)) => {
                let a_id = parse_snap_id(a_str)?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&a_id)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("snapshot:{}", &hex::encode(a_id)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
            (None, Some(b_str)) => {
                let head_cid = get_head_cid()?;
                let b_id = parse_snap_id(b_str)?;
                let old_map = decrypt_snap(&head_cid)?;
                let new_map = decrypt_snap(&b_id)?;
                (
                    format!("head:{}", &hex::encode(head_cid)[..8]),
                    format!("snapshot:{}", &hex::encode(b_id)[..8]),
                    old_map,
                    new_map,
                )
            }
        };

    let mut report = DiffReport::new(old_label, new_label);

    // Collect union of file paths
    let mut all_paths: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    for p in old_files.keys() {
        all_paths.insert(p.clone());
    }
    for p in new_files.keys() {
        all_paths.insert(p.clone());
    }

    for path in all_paths {
        if let Some(ref filter) = file_filter_opt {
            let norm_filter = filter.replace('\\', "/");
            if path != norm_filter && !path.ends_with(&format!("/{}", norm_filter)) {
                continue;
            }
        }

        let old_bytes = old_files.get(&path).cloned().unwrap_or_default();
        let new_bytes = new_files.get(&path).cloned().unwrap_or_default();

        let file_rep = diff_file_bytes(&path, &old_bytes, &new_bytes, reveal);
        report.add_file_report(file_rep);
    }

    Ok(report)
}

pub(crate) fn cmd_diff(
    snapshot_a_opt: Option<String>,
    snapshot_b_opt: Option<String>,
    file_filter_opt: Option<String>,
    reveal: bool,
    json_output: bool,
) -> Result<()> {
    let report = generate_diff_report(snapshot_a_opt, snapshot_b_opt, file_filter_opt, reveal)?;
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        print_diff_report(&report);
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le(text: &str) -> Vec<u8> {
        let mut bytes = vec![0xFF, 0xFE];
        for unit in text.encode_utf16() {
            bytes.extend_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    #[test]
    fn test_diff_file_bytes_utf16_never_reports_identical() {
        let old = utf16le("STRIPE_KEY=sk_test_123\n");
        let new = utf16le("STRIPE_KEY=sk_test_456\n");
        let report = diff_file_bytes(".env", &old, &new, false);
        assert!(
            report.added_count + report.removed_count + report.modified_count > 0,
            "changed UTF-16 dotenv must not diff as identical"
        );
    }

    #[test]
    fn test_mask_value() {
        assert_eq!(mask_value("short"), "***");
        assert_eq!(mask_value("12345678"), "12***78");
        assert_eq!(mask_value("token_test_51MzQ4xyz999"), "tok***999");
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
        let old_vars = vec![("SECRET".into(), "token_live_1234567890abcdef".into())];
        let new_vars = vec![("SECRET".into(), "token_live_0987654321fedcba".into())];

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
