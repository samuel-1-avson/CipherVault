//! Journaled publication of preverified plaintext. Interrupted publication rolls
//! back on the next restore/recovery call; a merge restore leaves unrelated files.
use crate::engine::{validate_no_links, validate_safe_relative_path, DecryptedFile};
use crate::SnapshotError;
use ciphervault_file_lock::{
    atomic_replace, create_secret_file, lock_secret_directory, sync_directory,
};
use ciphervault_format::compute_digest;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const STAGE: &str = ".ciphervault-restore";
const LOCK: &str = ".ciphervault-restore.lock";

#[derive(Serialize, Deserialize)]
struct Journal {
    version: u32,
    publishing: bool,
    committed: bool,
    entries: Vec<Entry>,
}
#[derive(Serialize, Deserialize)]
struct Entry {
    path: String,
    previous_digest: Option<[u8; 32]>,
    new_digest: [u8; 32],
}

fn acquire(target: &Path) -> Result<fs::File, SnapshotError> {
    validate_no_links(target)?;
    fs::create_dir_all(target)?;
    let lock_path = target.join(LOCK);
    validate_no_links(&lock_path)?;
    let lock = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(lock_path)?;
    lock.lock()?;
    Ok(lock)
}

fn write_journal(stage: &Path, journal: &Journal) -> Result<(), SnapshotError> {
    let path = stage.join("journal.json");
    let tmp = stage.join(format!("journal-{:032x}.tmp", rand::random::<u128>()));
    let result = (|| -> Result<(), SnapshotError> {
        let mut file = create_secret_file(&tmp)?;
        file.write_all(
            &serde_json::to_vec(journal).map_err(|e| SnapshotError::InvalidInput(e.to_string()))?,
        )?;
        file.sync_all()?;
        drop(file);
        atomic_replace(&tmp, &path)?;
        sync_directory(stage)?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn file_digest(path: &Path) -> Result<[u8; 32], SnapshotError> {
    let mut file = ciphervault_file_lock::open_regular_file(path)?;
    if file.metadata()?.len() > crate::MAX_FILE_SIZE {
        return Err(SnapshotError::FileTooLarge {
            path: path.display().to_string(),
            size: file.metadata()?.len(),
        });
    }
    let mut bytes = Zeroizing::new(Vec::new());
    (&mut file)
        .take(crate::MAX_FILE_SIZE + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > crate::MAX_FILE_SIZE {
        return Err(SnapshotError::FileTooLarge {
            path: path.display().to_string(),
            size: bytes.len() as u64,
        });
    }
    Ok(compute_digest(&bytes))
}

fn validate_destination(target: &Path, relative: &str) -> Result<PathBuf, SnapshotError> {
    validate_safe_relative_path(relative)?;
    if relative
        .split(['/', '\\'])
        .next()
        .is_some_and(|c| c.eq_ignore_ascii_case(STAGE) || c.eq_ignore_ascii_case(LOCK))
    {
        return Err(SnapshotError::UnsafePath(
            "Path reserved for restore transaction metadata".into(),
        ));
    }
    let path = target.join(relative);
    validate_no_links(&path)?;
    if let Ok(metadata) = fs::metadata(&path) {
        if !metadata.is_file() {
            return Err(SnapshotError::UnsafePath(format!(
                "Restore destination is not a regular file: {}",
                path.display()
            )));
        }
    }
    for parent in path.parent().into_iter().flat_map(Path::ancestors) {
        if parent == target {
            break;
        }
        match fs::metadata(parent) {
            Ok(meta) if !meta.is_dir() => {
                return Err(SnapshotError::UnsafePath(format!(
                    "Restore parent is not a directory: {}",
                    parent.display()
                )))
            }
            Err(error) if error.kind() != std::io::ErrorKind::NotFound => return Err(error.into()),
            _ => {}
        }
    }
    Ok(path)
}

fn rollback(target: &Path, stage: &Path, journal: &Journal) -> Result<(), SnapshotError> {
    for (index, entry) in journal.entries.iter().enumerate().rev() {
        let destination = validate_destination(target, &entry.path)?;
        if destination.exists() {
            let digest = file_digest(&destination)?;
            if digest != entry.new_digest && entry.previous_digest != Some(digest) {
                return Err(SnapshotError::InvalidInput(format!("Restore rollback stopped: {} changed outside this transaction; journal retained", destination.display())));
            }
        }
        if let Some(previous) = entry.previous_digest {
            let backup = stage.join(format!("backup-{index}"));
            if backup.exists() {
                if file_digest(&backup)? != previous {
                    return Err(SnapshotError::InvalidInput(
                        "Restore backup digest mismatch; journal retained".into(),
                    ));
                }
                // Keep backup until all rollback writes succeed, allowing another retry.
                let rollback_file =
                    stage.join(format!("rollback-{index}-{:032x}", rand::random::<u128>()));
                let mut file = create_secret_file(&rollback_file)?;
                let mut source = ciphervault_file_lock::open_regular_file(&backup)?;
                std::io::copy(&mut source, &mut file)?;
                file.sync_all()?;
                drop(file);
                atomic_replace(&rollback_file, &destination)?;
            } else {
                return Err(SnapshotError::InvalidInput(
                    "Restore backup missing; journal retained".into(),
                ));
            }
        } else if destination.exists() {
            fs::remove_file(&destination)?;
        }
        if let Some(parent) = destination.parent() {
            sync_directory(parent)?;
        }
    }
    Ok(())
}

fn recover_locked(target: &Path) -> Result<bool, SnapshotError> {
    let stage = target.join(STAGE);
    validate_no_links(&stage)?;
    if !stage.exists() {
        return Ok(false);
    }
    let journal_path = stage.join("journal.json");
    validate_no_links(&journal_path)?;
    if journal_path.exists() {
        let metadata = fs::metadata(&journal_path)?;
        if metadata.len() > 16 * 1024 * 1024 {
            return Err(SnapshotError::InvalidInput(
                "Restore journal is too large".into(),
            ));
        }
        let journal: Journal =
            serde_json::from_slice(&fs::read(&journal_path)?).map_err(|error| {
                SnapshotError::InvalidInput(format!("Invalid restore journal: {error}"))
            })?;
        if journal.version != 1 {
            return Err(SnapshotError::InvalidInput(
                "Unsupported restore journal version".into(),
            ));
        }
        if journal.publishing && !journal.committed {
            rollback(target, &stage, &journal)?;
        }
    }
    // No publication begins before a durable journal exists.
    fs::remove_dir_all(&stage)?;
    sync_directory(target)?;
    Ok(true)
}

/// Finish cleanup or roll back an interrupted restore before any new publication.
pub fn recover_interrupted_restore(target: &Path) -> Result<bool, SnapshotError> {
    let _lock = acquire(target)?;
    recover_locked(target)
}

pub(crate) fn publish_verified_files(
    target: &Path,
    files: &[DecryptedFile],
) -> Result<Vec<PathBuf>, SnapshotError> {
    publish_with(target, files, |_, source, destination| {
        atomic_replace(source, destination)
    })
}

fn publish_with(
    target: &Path,
    files: &[DecryptedFile],
    publish: impl Fn(usize, &Path, &Path) -> std::io::Result<()>,
) -> Result<Vec<PathBuf>, SnapshotError> {
    let _lock = acquire(target)?;
    recover_locked(target)?;
    let mut paths = Vec::with_capacity(files.len());
    let mut seen = std::collections::HashSet::new();
    for file in files {
        let portable = file.relative_path.replace('\\', "/");
        let normalized = Path::new(&portable)
            .components()
            .map(|component| component.as_os_str().to_string_lossy().to_ascii_lowercase())
            .collect::<Vec<_>>()
            .join("/");
        if !seen.insert(normalized) {
            return Err(SnapshotError::UnsafePath(
                "Duplicate restore destination".into(),
            ));
        }
        paths.push(validate_destination(target, &file.relative_path)?);
    }
    for path in &seen {
        if path
            .split('/')
            .scan(String::new(), |prefix, component| {
                if !prefix.is_empty() {
                    prefix.push('/');
                }
                prefix.push_str(component);
                Some(prefix.clone())
            })
            .any(|prefix| prefix != *path && seen.contains(&prefix))
        {
            return Err(SnapshotError::UnsafePath(
                "File/directory collision in restore destinations".into(),
            ));
        }
    }
    let stage = target.join(STAGE);
    fs::create_dir(&stage)?;
    lock_secret_directory(&stage)?;
    let mut journal = Journal {
        version: 1,
        publishing: false,
        committed: false,
        entries: Vec::new(),
    };
    let result = (|| -> Result<(), SnapshotError> {
        for (index, (file, destination)) in files.iter().zip(&paths).enumerate() {
            let mut staged = create_secret_file(&stage.join(format!("new-{index}")))?;
            staged.write_all(&file.plaintext)?;
            staged.sync_all()?;
            let previous_digest = if destination.exists() {
                let digest = file_digest(destination)?;
                let mut backup = create_secret_file(&stage.join(format!("backup-{index}")))?;
                let mut original = ciphervault_file_lock::open_regular_file(destination)?;
                std::io::copy(&mut original, &mut backup)?;
                backup.sync_all()?;
                if file_digest(&stage.join(format!("backup-{index}")))? != digest {
                    return Err(SnapshotError::ConcurrentModification(
                        file.relative_path.clone(),
                    ));
                }
                Some(digest)
            } else {
                None
            };
            journal.entries.push(Entry {
                path: file.relative_path.clone(),
                previous_digest,
                new_digest: compute_digest(&file.plaintext),
            });
            if let Some(parent) = destination.parent() {
                fs::create_dir_all(parent)?;
            }
        }
        journal.publishing = true;
        write_journal(&stage, &journal)?;
        for (index, destination) in paths.iter().enumerate() {
            validate_destination(target, &journal.entries[index].path)?;
            let current = if destination.exists() {
                Some(file_digest(destination)?)
            } else {
                None
            };
            if current != journal.entries[index].previous_digest {
                return Err(SnapshotError::ConcurrentModification(
                    journal.entries[index].path.clone(),
                ));
            }
            publish(index, &stage.join(format!("new-{index}")), destination)?;
            if let Some(parent) = destination.parent() {
                sync_directory(parent)?;
            }
        }
        journal.committed = true;
        write_journal(&stage, &journal)?;
        Ok(())
    })();
    if let Err(error) = result {
        if journal.publishing {
            rollback(target, &stage, &journal).map_err(|rollback| {
                SnapshotError::InvalidInput(format!(
                    "Restore failed ({error}); rollback failed ({rollback}); journal at {}",
                    stage.display()
                ))
            })?;
        }
        fs::remove_dir_all(&stage)?;
        return Err(error);
    }
    fs::remove_dir_all(stage)?;
    sync_directory(target)?;
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interrupted_publication_is_recoverable_and_respects_external_changes() {
        let root =
            std::env::temp_dir().join(format!("cv-restore-crash-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&root).unwrap();
        let stage = root.join(STAGE);
        fs::create_dir(&stage).unwrap();
        lock_secret_directory(&stage).unwrap();
        let mut backup = create_secret_file(&stage.join("backup-0")).unwrap();
        backup.write_all(b"old-a").unwrap();
        backup.sync_all().unwrap();
        drop(backup);
        fs::write(root.join("a.env"), b"new-a").unwrap();
        fs::write(root.join("b.env"), b"new-b").unwrap();
        let journal = Journal {
            version: 1,
            publishing: true,
            committed: false,
            entries: vec![
                Entry {
                    path: "a.env".into(),
                    previous_digest: Some(compute_digest(b"old-a")),
                    new_digest: compute_digest(b"new-a"),
                },
                Entry {
                    path: "b.env".into(),
                    previous_digest: None,
                    new_digest: compute_digest(b"new-b"),
                },
            ],
        };
        write_journal(&stage, &journal).unwrap();
        // A different process's edit must survive failed rollback.
        fs::write(root.join("a.env"), b"external edit").unwrap();
        assert!(recover_interrupted_restore(&root).is_err());
        assert_eq!(fs::read(root.join("a.env")).unwrap(), b"external edit");
        assert!(stage.join("journal.json").exists());
        fs::write(root.join("a.env"), b"new-a").unwrap();
        assert!(recover_interrupted_restore(&root).unwrap());
        assert_eq!(fs::read(root.join("a.env")).unwrap(), b"old-a");
        assert!(!root.join("b.env").exists());
        assert!(!stage.exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn published_secret_has_restrictive_windows_acl() {
        let root =
            std::env::temp_dir().join(format!("cv-restore-acl-{:032x}", rand::random::<u128>()));
        let files = vec![DecryptedFile {
            relative_path: "secret.env".into(),
            plaintext: b"SYNTHETIC=value".to_vec(),
        }];
        publish_verified_files(&root, &files).unwrap();
        let query = std::process::Command::new("icacls")
            .arg(root.join("secret.env"))
            .output()
            .unwrap();
        assert!(query.status.success());
        let listing = String::from_utf8_lossy(&query.stdout).to_ascii_lowercase();
        assert!(listing.contains(&std::env::var("USERNAME").unwrap().to_ascii_lowercase()));
        assert!(!listing.contains("builtin"), "{listing}");
        assert!(!listing.contains("(i)"), "{listing}");
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn publication_failure_restores_all_originals() {
        let root =
            std::env::temp_dir().join(format!("cv-restore-fail-{:032x}", rand::random::<u128>()));
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("a.env"), b"old-a").unwrap();
        let files = vec![
            DecryptedFile {
                relative_path: "a.env".into(),
                plaintext: b"new-a".to_vec(),
            },
            DecryptedFile {
                relative_path: "b.env".into(),
                plaintext: b"new-b".to_vec(),
            },
        ];
        assert!(publish_with(&root, &files, |index, source, destination| {
            if index == 1 {
                Err(std::io::Error::other("injected publication failure"))
            } else {
                atomic_replace(source, destination)
            }
        })
        .is_err());
        assert_eq!(fs::read(root.join("a.env")).unwrap(), b"old-a");
        assert!(!root.join("b.env").exists());
        assert!(!root.join(STAGE).exists());
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unsafe_late_destination_never_publishes_earlier_files() {
        let root = std::env::temp_dir().join(format!(
            "cv-restore-preflight-{:032x}",
            rand::random::<u128>()
        ));
        fs::create_dir_all(root.join("blocked")).unwrap();
        fs::write(root.join("a.env"), b"old-a").unwrap();
        let files = vec![
            DecryptedFile {
                relative_path: "a.env".into(),
                plaintext: b"new-a".to_vec(),
            },
            DecryptedFile {
                relative_path: "blocked".into(),
                plaintext: b"new-b".to_vec(),
            },
        ];
        assert!(publish_verified_files(&root, &files).is_err());
        assert_eq!(fs::read(root.join("a.env")).unwrap(), b"old-a");
        fs::remove_dir_all(root).unwrap();
    }
}
