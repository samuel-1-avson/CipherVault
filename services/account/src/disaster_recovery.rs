//! Offline, consistent account database backups and isolated recovery drills.
//!
//! The backup receipt detects accidental corruption; it is not a signature.
//! Keys are supplied separately and never copied into the backup bundle.

use std::collections::BTreeMap;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ciphervault_crypto::{
    open_secret_value, scope_aad, KeyWrappingService, SealedSecret, WrappedDek, NONCE_SIZE,
    TAG_SIZE,
};
use ciphervault_file_lock::{
    create_secret_file, lock_secret_directory, open_regular_file, sync_directory,
};
use rusqlite::{backup::Backup, backup::StepResult, Connection, OpenFlags};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::{key_lifecycle::VersionedKekService, AccountServiceError};

const DATABASE: &str = "accounts.sqlite3";
const RECEIPT: &str = "backup-receipt.json";
const MAX_KEY_FILE_BYTES: u64 = 64 * 1024;
const TABLES: &[&str] = &[
    "accounts",
    "devices",
    "webauthn_credentials",
    "totp_credentials",
    "sessions",
    "organizations",
    "projects",
    "environments",
    "secrets",
    "secret_versions",
    "encryption_keys",
    "secret_access_events",
    "recovery_codes",
    "scope_token_denylist",
];

#[derive(Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct BackupReceipt {
    pub format_version: u32,
    pub created_at_utc: u64,
    pub database_sha256: String,
    pub database_bytes: u64,
    pub table_rows: BTreeMap<String, u64>,
    pub audit_chains_checked: u64,
}

#[derive(Debug, Serialize)]
pub struct RecoveryRehearsalReport {
    pub status: &'static str,
    pub backup_sha256: String,
    pub table_rows: BTreeMap<String, u64>,
    pub audit_chains_checked: u64,
    pub secret_versions_decrypted: u64,
    pub totp_seeds_decrypted: u64,
    pub copied_sessions_revoked: u64,
    pub production_modified: bool,
    pub keys_included: bool,
}

fn invalid(message: &str) -> AccountServiceError {
    AccountServiceError::Invalid(message.into())
}

/// Reject symlinks and Windows reparse points throughout an existing path.
pub(crate) fn checked_existing(path: &Path) -> Result<PathBuf, AccountServiceError> {
    let absolute = std::path::absolute(path)?;
    for ancestor in absolute.ancestors() {
        let metadata = fs::symlink_metadata(ancestor)?;
        if metadata.file_type().is_symlink() {
            // Darwin's standard system aliases are immutable platform layout,
            // including the prefix used by std::env::temp_dir(). Keep rejecting
            // caller-controlled symlinks below those prefixes.
            #[cfg(target_os = "macos")]
            if [
                (Path::new("/var"), Path::new("/private/var")),
                (Path::new("/tmp"), Path::new("/private/tmp")),
                (Path::new("/etc"), Path::new("/private/etc")),
            ]
            .iter()
            .any(|(alias, target)| {
                ancestor == *alias && fs::canonicalize(alias).ok().as_deref() == Some(*target)
            }) {
                continue;
            }
            return Err(invalid("backup paths must not contain symlinks"));
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::MetadataExt;
            if metadata.file_attributes() & 0x400 != 0 {
                return Err(invalid("backup paths must not contain reparse points"));
            }
        }
    }
    Ok(absolute)
}

fn new_private_directory(path: &Path) -> Result<PathBuf, AccountServiceError> {
    let absolute = std::path::absolute(path)?;
    let parent = absolute
        .parent()
        .ok_or_else(|| invalid("output directory requires a parent"))?;
    checked_existing(parent)?;
    // create_dir, rather than create_dir_all, also rejects an existing directory.
    fs::create_dir(&absolute)?;
    if let Err(error) = lock_secret_directory(&absolute) {
        let _ = fs::remove_dir(&absolute);
        return Err(error.into());
    }
    sync_directory(parent)?;
    Ok(absolute)
}

/// Validate SQLite paths without opening/closing a raw descriptor. On POSIX,
/// closing a second descriptor can release locks held by a live connection.
pub(crate) fn checked_regular_database_path(path: &Path) -> Result<PathBuf, AccountServiceError> {
    let path = checked_existing(path)?;
    if !fs::symlink_metadata(&path)?.is_file() {
        return Err(invalid("SQLite paths must be regular files"));
    }
    // Resolve permitted immutable macOS aliases only after rejecting unsafe
    // caller-controlled links, so SQLite's NOFOLLOW also sees safe ancestors.
    Ok(fs::canonicalize(path)?)
}

fn readonly_database(path: &Path) -> Result<Connection, AccountServiceError> {
    let path = checked_regular_database_path(path)?;
    let db = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NOFOLLOW,
    )?;
    db.busy_timeout(Duration::from_secs(5))?;
    Ok(db)
}

fn copy_consistent(source: &Connection, target: &Path) -> Result<(), AccountServiceError> {
    let protected_file = create_secret_file(target)?;
    let mut destination = Connection::open_with_flags(target, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    destination.busy_timeout(Duration::from_secs(5))?;
    // Pin the source read transaction so online writes cannot restart the
    // backup forever or mix different revisions of the database.
    source.execute_batch("BEGIN")?;
    source.query_row("SELECT COUNT(*) FROM sqlite_master", [], |row| {
        row.get::<_, i64>(0)
    })?;
    let result = (|| {
        let backup = Backup::new(source, &mut destination)?;
        let deadline = Instant::now() + Duration::from_secs(120);
        loop {
            match backup.step(512)? {
                StepResult::Done => break,
                StepResult::More if Instant::now() < deadline => {}
                StepResult::Busy | StepResult::Locked if Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                _ => {
                    return Err(invalid(
                        "consistent database backup did not complete within 120 seconds",
                    ))
                }
            }
        }
        Ok::<_, AccountServiceError>(())
    })();
    source.execute_batch("ROLLBACK")?;
    result?;
    // The artifact is self-contained; its WAL is checkpointed before publish.
    destination.execute_batch("PRAGMA journal_mode=DELETE; PRAGMA synchronous=FULL")?;
    drop(destination);
    protected_file.sync_all()?;
    sync_directory(
        target
            .parent()
            .ok_or_else(|| invalid("missing output parent"))?,
    )?;
    Ok(())
}

fn validate_database(db: &Connection) -> Result<(BTreeMap<String, u64>, u64), AccountServiceError> {
    let mut check = db.prepare("PRAGMA integrity_check")?;
    let mut rows = check.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let result: String = row.get(0)?;
        if result != "ok" {
            return Err(invalid("account database integrity verification failed"));
        }
        count += 1;
    }
    if count != 1 {
        return Err(invalid("account database integrity verification failed"));
    }
    let mut foreign_keys = db.prepare("PRAGMA foreign_key_check")?;
    if foreign_keys.query([])?.next()?.is_some() {
        return Err(invalid("account database foreign-key verification failed"));
    }
    let mut counts = BTreeMap::new();
    for table in TABLES {
        // Only this fixed, internal table list is interpolated.
        let count: u64 = db.query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
            row.get(0)
        })?;
        counts.insert((*table).into(), count);
    }
    let mut tenant_statement = db.prepare("SELECT DISTINCT tenant_id FROM secret_access_events")?;
    let tenants = tenant_statement.query_map([], |row| row.get::<_, String>(0))?;
    let mut chains = 0;
    for tenant in tenants {
        if !crate::audit_chain::verify_chain(db, &tenant?)?.valid {
            return Err(invalid("account database audit-chain verification failed"));
        }
        chains += 1;
    }
    Ok((counts, chains))
}

fn digest_file(path: &Path) -> Result<(String, u64), AccountServiceError> {
    let mut file = open_regular_file(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0;
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        bytes += count as u64;
    }
    Ok((hex::encode(hasher.finalize()), bytes))
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<(), AccountServiceError> {
    let json = serde_json::to_vec_pretty(value)
        .map_err(|_| invalid("could not serialize backup report"))?;
    let mut file = create_secret_file(path)?;
    file.write_all(&json)?;
    file.write_all(b"\n")?;
    file.sync_all()?;
    sync_directory(
        path.parent()
            .ok_or_else(|| invalid("missing report parent"))?,
    )?;
    Ok(())
}

/// Back up an existing account service without schema migration or key access.
/// The output directory must not exist. A receipt is written only after all
/// structural and audit checks pass; failed output is retained for diagnosis.
pub fn backup_accounts(
    data_dir: &Path,
    output_dir: &Path,
) -> Result<BackupReceipt, AccountServiceError> {
    let source = readonly_database(&data_dir.join(DATABASE))?;
    let output = new_private_directory(output_dir)?;
    let database = output.join(DATABASE);
    copy_consistent(&source, &database)?;
    let restored = readonly_database(&database)?;
    let (table_rows, audit_chains_checked) = validate_database(&restored)?;
    drop(restored);
    let (database_sha256, database_bytes) = digest_file(&database)?;
    let receipt = BackupReceipt {
        format_version: 1,
        created_at_utc: crate::state::now_utc(),
        database_sha256,
        database_bytes,
        table_rows,
        audit_chains_checked,
    };
    write_json(&output.join(RECEIPT), &receipt)?;
    Ok(receipt)
}

fn read_key_file(path: &Path) -> Result<Zeroizing<String>, AccountServiceError> {
    let path = checked_existing(path)?;
    let mut file = open_regular_file(&path)?.take(MAX_KEY_FILE_BYTES + 1);
    let mut value = Zeroizing::new(String::new());
    file.read_to_string(&mut value)?;
    if value.len() as u64 > MAX_KEY_FILE_BYTES {
        return Err(invalid("key file exceeds 64 KiB"));
    }
    Ok(value)
}

fn scope_id(value: &str) -> Result<[u8; 16], AccountServiceError> {
    hex::decode(value)
        .ok()
        .and_then(|value| value.try_into().ok())
        .ok_or_else(|| invalid("restored secret scope identifier is invalid"))
}

fn check_envelopes(db: &Connection, raw_key: Option<&str>) -> Result<u64, AccountServiceError> {
    let mut statement = db.prepare("SELECT v.secret_id, v.version, v.encryption_key_id, v.nonce,
        v.ciphertext, v.wrapped_dek, v.value_sha256, s.tenant_id, s.project_id, s.environment_id
        FROM secret_versions v JOIN secrets s ON s.secret_id = v.secret_id ORDER BY s.project_id, v.rowid")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    let mut previous_project = String::new();
    let mut wrap = None;
    while let Some(row) = rows.next()? {
        let secret: String = row.get(0)?;
        let version: i64 = row.get(1)?;
        let project: String = row.get(8)?;
        if project != previous_project {
            let service = VersionedKekService::from_config(
                &project,
                raw_key.ok_or_else(|| {
                    invalid("restore verification requires the separate historical KEK file")
                })?,
            )
            .map_err(|_| invalid("restore KEK configuration is invalid"))?;
            service
                .verify_registered_identities(db)
                .map_err(|_| invalid("restore KEK identity does not match the database"))?;
            wrap = Some(service);
            previous_project = project.clone();
        }
        let blob: Vec<u8> = row.get(5)?;
        if blob.len() < NONCE_SIZE + TAG_SIZE {
            return Err(invalid(
                "restored DEK envelope is malformed or predates envelope storage",
            ));
        }
        let dek = wrap
            .as_ref()
            .ok_or_else(|| invalid("missing restore KEK"))?
            .unwrap_dek(&WrappedDek {
                kek_id: row.get(2)?,
                nonce: blob[..NONCE_SIZE]
                    .try_into()
                    .map_err(|_| invalid("invalid wrapped nonce"))?,
                blob: blob[NONCE_SIZE..].to_vec(),
            })
            .map_err(|_| {
                invalid("historical KEK is missing or cannot authenticate a restored DEK")
            })?;
        let nonce: Vec<u8> = row.get(3)?;
        let sealed = SealedSecret {
            nonce: nonce
                .try_into()
                .map_err(|_| invalid("restored value nonce is invalid"))?,
            ciphertext: row.get(4)?,
        };
        let digest: Vec<u8> = row.get(6)?;
        let tenant: String = row.get(7)?;
        let current_environment: String = row.get(9)?;
        // Scope moves preserve earlier envelopes under their original AAD.
        // Their authenticated audit entries retain the original environment.
        let mut candidates = vec![current_environment];
        let mut environments = db.prepare(
            "SELECT DISTINCT environment_id FROM secret_access_events
            WHERE secret_id = ?1 AND secret_version = ?2 AND environment_id IS NOT NULL LIMIT 129",
        )?;
        for value in environments.query_map(rusqlite::params![secret, version], |row| {
            row.get::<_, String>(0)
        })? {
            let value = value?;
            if !candidates.contains(&value) {
                candidates.push(value);
            }
        }
        if candidates.len() > 128 {
            return Err(invalid("historical scope candidate limit exceeded"));
        }
        let mut verified = false;
        for environment in candidates {
            let aad = scope_aad(
                &scope_id(&tenant)?,
                &scope_id(&project)?,
                &scope_id(&environment)?,
                &scope_id(&secret)?,
                u32::try_from(version).map_err(|_| invalid("restored version is invalid"))?,
            );
            if let Ok(plaintext) = open_secret_value(&dek, &sealed, &aad) {
                let plaintext = Zeroizing::new(plaintext);
                if Sha256::digest(&plaintext).as_slice() != digest {
                    return Err(invalid("restored plaintext digest does not match"));
                }
                verified = true;
                break;
            }
        }
        if !verified {
            return Err(invalid(
                "restored secret version failed scope-bound authentication",
            ));
        }
        count += 1;
    }
    Ok(count)
}

fn check_totp(db: &Connection, raw_key: Option<&str>) -> Result<u64, AccountServiceError> {
    let mut statement = db.prepare("SELECT secret_ciphertext_b64 FROM totp_credentials")?;
    let mut rows = statement.query([])?;
    let mut count = 0;
    while let Some(row) = rows.next()? {
        let decoded = Zeroizing::new(
            hex::decode(
                raw_key
                    .ok_or_else(|| {
                        invalid("restore verification requires the separate TOTP wrapping-key file")
                    })?
                    .trim(),
            )
            .map_err(|_| invalid("restore TOTP wrapping key is malformed"))?,
        );
        let key: Zeroizing<[u8; 32]> = Zeroizing::new(
            decoded
                .as_slice()
                .try_into()
                .map_err(|_| invalid("restore TOTP wrapping key must be 32 bytes"))?,
        );
        let seed = Zeroizing::new(
            crate::totp::decrypt_totp_secret_with_key(&row.get::<_, String>(0)?, &key)
                .map_err(|_| invalid("restored TOTP seed failed authentication"))?,
        );
        if seed.is_empty() {
            return Err(invalid("restored TOTP seed is empty"));
        }
        count += 1;
    }
    Ok(count)
}

/// Restore into a NEW owner-only directory, verify every retained value and
/// TOTP seed in memory, and revoke copied sessions. No HTTP listener is opened,
/// no production database is modified, and no keys or plaintext are exported.
pub fn rehearse_restore(
    backup_dir: &Path,
    output_dir: &Path,
    kek_file: Option<&Path>,
    totp_key_file: Option<&Path>,
) -> Result<RecoveryRehearsalReport, AccountServiceError> {
    let backup_dir = checked_existing(backup_dir)?;
    let mut file = open_regular_file(&backup_dir.join(RECEIPT))?.take(64 * 1024 + 1);
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    if bytes.len() > 64 * 1024 {
        return Err(invalid("backup receipt exceeds 64 KiB"));
    }
    let receipt: BackupReceipt =
        serde_json::from_slice(&bytes).map_err(|_| invalid("backup receipt is malformed"))?;
    if receipt.format_version != 1 {
        return Err(invalid("backup receipt version is unsupported"));
    }
    let database = backup_dir.join(DATABASE);
    let (digest, length) = digest_file(&database)?;
    if digest != receipt.database_sha256 || length != receipt.database_bytes {
        return Err(invalid("backup checksum does not match its receipt"));
    }
    for suffix in ["-wal", "-shm", "-journal"] {
        if backup_dir
            .join(format!("{DATABASE}{suffix}"))
            .try_exists()?
        {
            return Err(invalid("backup bundle is not a self-contained database"));
        }
    }
    let output = new_private_directory(output_dir)?;
    let copied = output.join(DATABASE);
    let mut source_file = open_regular_file(&database)?;
    let mut copied_file = create_secret_file(&copied)?;
    std::io::copy(&mut source_file, &mut copied_file)?;
    copied_file.sync_all()?;
    drop(copied_file);
    // Recheck the artifact actually restored, closing the race between the
    // source checksum and the pinned SQLite snapshot.
    if digest_file(&copied)? != (receipt.database_sha256.clone(), receipt.database_bytes) {
        return Err(invalid(
            "restored backup checksum does not match its receipt",
        ));
    }
    let mut restored = Connection::open_with_flags(&copied, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    let (table_rows, audit_chains_checked) = validate_database(&restored)?;
    if table_rows != receipt.table_rows || audit_chains_checked != receipt.audit_chains_checked {
        return Err(invalid(
            "restored database inventory does not match its receipt",
        ));
    }
    let kek = kek_file.map(read_key_file).transpose()?;
    let totp = totp_key_file.map(read_key_file).transpose()?;
    let secret_versions_decrypted = check_envelopes(&restored, kek.as_deref().map(|v| v.as_str()))?;
    let totp_seeds_decrypted = check_totp(&restored, totp.as_deref().map(|v| v.as_str()))?;
    let transaction = restored.transaction()?;
    let copied_sessions_revoked = transaction.execute(
        "UPDATE sessions SET revoked_at_utc = ?1 WHERE revoked_at_utc IS NULL",
        [crate::state::now_utc()],
    )? as u64;
    transaction.execute_batch(
        "DELETE FROM challenges; DELETE FROM session_handoffs; DELETE FROM dpop_proofs",
    )?;
    transaction.commit()?;
    drop(restored);
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&copied)?
        .sync_all()?;
    let report = RecoveryRehearsalReport {
        status: "verified_isolated_restore",
        backup_sha256: digest,
        table_rows,
        audit_chains_checked,
        secret_versions_decrypted,
        totp_seeds_decrypted,
        copied_sessions_revoked,
        production_modified: false,
        keys_included: false,
    };
    write_json(&output.join("rehearsal-report.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{grant_project_role, ProjectRole, RequestAttributes};
    use crate::scope_tokens::ScopeClaims;
    use crate::secrets::{create_secret, move_secret, CreateSecret, MoveSecret};
    use crate::test_support::{cleanup, test_app};
    use ciphervault_format::{EnvironmentId, ProjectId, SecretValue, TenantId};
    use rusqlite::params;

    fn key_file(root: &Path, name: &str, value: &str) -> PathBuf {
        let path = root.join(name);
        let mut file = create_secret_file(&path).unwrap();
        file.write_all(value.as_bytes()).unwrap();
        file.sync_all().unwrap();
        path
    }

    fn seed_encrypted_versions(db: &mut Connection) {
        let tenant = TenantId::generate().to_hex();
        let project = ProjectId::generate().to_hex();
        let env = EnvironmentId::generate().to_hex();
        let next_env = EnvironmentId::generate().to_hex();
        db.execute("INSERT INTO organizations VALUES(?1, 'test', 1)", [&tenant])
            .unwrap();
        db.execute(
            "INSERT INTO workspaces VALUES('w1', ?1, 'test', 1)",
            [&tenant],
        )
        .unwrap();
        db.execute(
            "INSERT INTO projects(project_id, tenant_id, workspace_id, slug, name, created_at_utc)
            VALUES(?1, ?2, 'w1', 'test', 'test', 1)",
            params![project, tenant],
        )
        .unwrap();
        for (id, slug) in [(&env, "first"), (&next_env, "second")] {
            db.execute("INSERT INTO environments(environment_id, tenant_id, project_id, slug, tier, created_at_utc)
                VALUES(?1, ?2, ?3, ?4, 0, 1)", params![id, tenant, project, slug]).unwrap();
        }
        grant_project_role(db, &project, "account:alice", ProjectRole::Admin, "root", 1).unwrap();
        let claims = ScopeClaims::new(&tenant, &project, "account:alice", 1, u64::MAX);
        let wrap = VersionedKekService::from_config(&project, &"11".repeat(32)).unwrap();
        wrap.register(db, &project).unwrap();
        let attrs = RequestAttributes {
            human_session: true,
            recent_strong_auth: true,
            ..RequestAttributes::default()
        };
        let secret = create_secret(
            db,
            &wrap,
            wrap.active_id(),
            &claims,
            &attrs,
            &CreateSecret {
                project_id: &project,
                environment_id: &env,
                name: "DRILL_VALUE",
                secret_type: "key_value",
                description: "",
                tags: &[],
                repository_binding_id: None,
                service_id: None,
                value: &SecretValue::from("synthetic-value-never-exported"),
                request_id: "create",
            },
        )
        .unwrap();
        move_secret(
            db,
            &wrap,
            wrap.active_id(),
            &claims,
            &attrs,
            &secret.secret_id,
            &MoveSecret {
                new_name: None,
                new_environment_id: Some(&next_env),
                reason: "scope move fixture",
                request_id: "move",
            },
        )
        .unwrap();
    }

    #[test]
    fn online_wal_backup_and_rehearsal_verify_historical_scopes_without_production_changes() {
        let (root, state, app) = test_app("dr-wal");
        {
            let mut db = state.connection().unwrap();
            seed_encrypted_versions(&mut db);
            db.execute(
                "INSERT INTO accounts VALUES('cvacct_dr', 'Test', ?1, 1)",
                ["aa".repeat(32)],
            )
            .unwrap();
            db.execute(
                "INSERT INTO sessions(token_hash_hex, account_id, issued_at_utc, expires_at_utc)
                VALUES('session-hash', 'cvacct_dr', 1, 9999999999)",
                [],
            )
            .unwrap();
        }
        assert!(root.join("accounts.sqlite3-wal").exists());
        let backup = root.join("backup");
        let receipt = backup_accounts(&root, &backup).unwrap();
        assert_eq!(receipt.table_rows["secret_versions"], 2);
        let key = key_file(&root, "key", &"11".repeat(32));
        let restored = root.join("rehearsal");
        let result = rehearse_restore(&backup, &restored, Some(&key), None).unwrap();
        assert_eq!(result.secret_versions_decrypted, 2);
        assert_eq!(result.copied_sessions_revoked, 1);
        assert!(!result.production_modified);
        assert!(!result.keys_included);
        let revoked: Option<i64> = state
            .connection()
            .unwrap()
            .query_row(
                "SELECT revoked_at_utc FROM sessions WHERE token_hash_hex = 'session-hash'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(revoked, None);
        assert_eq!(
            digest_file(&backup.join(DATABASE)).unwrap().0,
            receipt.database_sha256
        );
        let serialized = fs::read_to_string(restored.join("rehearsal-report.json")).unwrap();
        assert!(!serialized.contains("synthetic-value-never-exported"));
        assert!(!serialized.contains(&"11".repeat(32)));
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn wrong_or_missing_kek_fails_without_success_report_or_changes_to_source() {
        let (root, state, app) = test_app("dr-wrong-key");
        seed_encrypted_versions(&mut state.connection().unwrap());
        let backup = root.join("backup");
        backup_accounts(&root, &backup).unwrap();
        let before = digest_file(&backup.join(DATABASE)).unwrap();
        let wrong = key_file(&root, "wrong-key", &"22".repeat(32));
        let result = rehearse_restore(&backup, &root.join("wrong"), Some(&wrong), None);
        assert!(result.unwrap_err().to_string().contains("KEK identity"));
        assert!(!root.join("wrong/rehearsal-report.json").exists());
        assert!(rehearse_restore(&backup, &root.join("missing"), None, None).is_err());
        assert_eq!(before, digest_file(&backup.join(DATABASE)).unwrap());
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn historical_database_without_key_fingerprints_is_verified_without_migration() {
        let (root, state, app) = test_app("dr-pre-fingerprints");
        {
            let mut db = state.connection().unwrap();
            seed_encrypted_versions(&mut db);
            db.execute_batch("ALTER TABLE encryption_keys DROP COLUMN key_fingerprint")
                .unwrap();
        }
        let backup = root.join("backup");
        backup_accounts(&root, &backup).unwrap();
        let key = key_file(&root, "key", &"11".repeat(32));
        let report = rehearse_restore(&backup, &root.join("rehearsal"), Some(&key), None).unwrap();
        assert_eq!(report.secret_versions_decrypted, 2);
        let has_fingerprints: bool = state.connection().unwrap().query_row(
            "SELECT EXISTS(SELECT 1 FROM pragma_table_info('encryption_keys') WHERE name = 'key_fingerprint')",
            [], |row| row.get(0)).unwrap();
        assert!(!has_fingerprints);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn corrupted_audit_chain_does_not_publish_a_complete_backup() {
        let (root, state, app) = test_app("dr-corrupt-audit");
        {
            let mut db = state.connection().unwrap();
            seed_encrypted_versions(&mut db);
            db.execute_batch(
                "DROP TRIGGER secret_access_events_no_update;
                UPDATE secret_access_events SET reason = 'rewritten'",
            )
            .unwrap();
        }
        let backup = root.join("backup");
        assert!(backup_accounts(&root, &backup)
            .unwrap_err()
            .to_string()
            .contains("audit-chain"));
        assert!(!backup.join(RECEIPT).exists());
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn corruption_and_existing_outputs_fail_closed() {
        let (root, state, app) = test_app("dr-corruption");
        let backup = root.join("backup");
        backup_accounts(&root, &backup).unwrap();
        assert!(backup_accounts(&root, &backup).is_err());
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(backup.join(DATABASE))
            .unwrap();
        file.write_all(b"corruption").unwrap();
        drop(file);
        let output = root.join("rehearsal");
        assert!(rehearse_restore(&backup, &output, None, None)
            .unwrap_err()
            .to_string()
            .contains("checksum"));
        assert!(!output.exists());
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn invalid_database_does_not_publish_backup_receipt() {
        let (root, state, app) = test_app("dr-invalid");
        state
            .connection()
            .unwrap()
            .execute_batch(
                "PRAGMA foreign_keys=OFF;
            INSERT INTO devices(account_id, device_id_hex, public_key_hex, label, enrolled_at_utc)
            VALUES('missing-account', 'd', 'p', 'test', 1)",
            )
            .unwrap();
        let backup = root.join("backup");
        assert!(backup_accounts(&root, &backup)
            .unwrap_err()
            .to_string()
            .contains("foreign-key"));
        assert!(!backup.join(RECEIPT).exists());
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[test]
    fn totp_seed_recovery_requires_the_correct_separate_key() {
        let (root, state, app) = test_app("dr-totp");
        let key = ring::aead::UnboundKey::new(&ring::aead::AES_256_GCM, &[0x33; 32]).unwrap();
        let key = ring::aead::LessSafeKey::new(key);
        let nonce = [0x44; 12];
        let mut payload = b"synthetic-totp-seed".to_vec();
        key.seal_in_place_append_tag(
            ring::aead::Nonce::assume_unique_for_key(nonce),
            ring::aead::Aad::empty(),
            &mut payload,
        )
        .unwrap();
        let mut envelope = nonce.to_vec();
        envelope.extend_from_slice(&payload);
        {
            let db = state.connection().unwrap();
            db.execute(
                "INSERT INTO accounts VALUES('cvacct_dr', 'Test', ?1, 1)",
                ["aa".repeat(32)],
            )
            .unwrap();
            db.execute("INSERT INTO totp_credentials(account_id, secret_ciphertext_b64, enabled, created_at_utc)
                VALUES('cvacct_dr', ?1, 1, 1)", [crate::b64_encode(&envelope)]).unwrap();
        }
        let backup = root.join("backup");
        backup_accounts(&root, &backup).unwrap();
        let right = key_file(&root, "totp-key", &"33".repeat(32));
        let wrong = key_file(&root, "wrong-key", &"22".repeat(32));
        assert!(rehearse_restore(&backup, &root.join("missing"), None, None).is_err());
        assert!(rehearse_restore(&backup, &root.join("wrong"), None, Some(&wrong)).is_err());
        let report = rehearse_restore(&backup, &root.join("right"), None, Some(&right)).unwrap();
        assert_eq!(report.totp_seeds_decrypted, 1);
        assert_eq!(report.secret_versions_decrypted, 0);
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[cfg(unix)]
    #[test]
    fn account_directory_sidecars_and_backup_are_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let (root, state, app) = test_app("dr-permissions");
        for suffix in ["", "-wal", "-shm"] {
            let path = root.join(format!("accounts.sqlite3{suffix}"));
            if path.exists() {
                assert_eq!(
                    fs::metadata(path).unwrap().permissions().mode() & 0o777,
                    0o600
                );
            }
        }
        assert_eq!(
            fs::metadata(&root).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let backup = root.join("backup");
        backup_accounts(&root, &backup).unwrap();
        assert_eq!(
            fs::metadata(&backup).unwrap().permissions().mode() & 0o777,
            0o700
        );
        for name in [DATABASE, RECEIPT] {
            assert_eq!(
                fs::metadata(backup.join(name))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        drop(app);
        drop(state);
        cleanup(root);
    }

    #[cfg(unix)]
    #[test]
    fn backup_and_restore_reject_symlink_paths() {
        use std::os::unix::fs::symlink;
        let (root, state, app) = test_app("dr-symlink");
        let alias = root.join("alias");
        symlink(&root, &alias).unwrap();
        assert!(backup_accounts(&alias, &root.join("rejected")).is_err());
        assert!(!root.join("rejected").exists());
        drop(app);
        drop(state);
        cleanup(root);
    }
}
