use std::fs;
use std::process::Command;

use ciphervault_account::AccountState;
use rand::RngCore;
use rusqlite::{params, Connection};

#[test]
fn offline_commands_recover_an_isolated_copy_and_never_bind_http() {
    let mut nonce = [0u8; 8];
    rand::thread_rng().fill_bytes(&mut nonce);
    let root = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("cv-account-cli-dr-{}", hex::encode(nonce)));
    let source = root.join("source");
    let state = AccountState::open(&source).unwrap();
    let connection = Connection::open(source.join("accounts.sqlite3")).unwrap();
    connection
        .execute(
            "INSERT INTO accounts VALUES('account', 'Synthetic', ?1, 1)",
            ["aa".repeat(32)],
        )
        .unwrap();
    connection
        .execute(
            "INSERT INTO sessions(token_hash_hex, account_id, issued_at_utc, expires_at_utc)
        VALUES(?1, 'account', 1, 9999999999)",
            params!["synthetic-session-hash"],
        )
        .unwrap();
    let binary = env!("CARGO_BIN_EXE_ciphervault-account");
    let backup = root.join("backup");
    let result = Command::new(binary)
        .args(["backup", "--data-dir"])
        .arg(&source)
        .arg("--output-dir")
        .arg(&backup)
        .env(
            "CIPHERVAULT_ACCOUNT_BIND",
            "invalid-bind-must-never-be-read",
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let receipt: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(receipt["table_rows"]["sessions"], 1);
    let restored = root.join("restored");
    let result = Command::new(binary)
        .args(["restore-rehearsal", "--backup-dir"])
        .arg(&backup)
        .arg("--output-dir")
        .arg(&restored)
        .env(
            "CIPHERVAULT_ACCOUNT_BIND",
            "invalid-bind-must-never-be-read",
        )
        .output()
        .unwrap();
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["status"], "verified_isolated_restore");
    assert_eq!(report["copied_sessions_revoked"], 1);
    assert_eq!(report["production_modified"], false);
    assert_eq!(report["keys_included"], false);
    let original_revoked: Option<i64> = connection
        .query_row("SELECT revoked_at_utc FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert!(original_revoked.is_none());
    let restored_db = Connection::open(restored.join("accounts.sqlite3")).unwrap();
    let restored_revoked: Option<i64> = restored_db
        .query_row("SELECT revoked_at_utc FROM sessions", [], |row| row.get(0))
        .unwrap();
    assert!(restored_revoked.is_some());
    let failed = Command::new(binary)
        .args(["restore-rehearsal", "--backup-dir"])
        .arg(&backup)
        .arg("--output-dir")
        .arg(&source)
        .output()
        .unwrap();
    assert!(!failed.status.success());
    assert!(!source.join("rehearsal-report.json").exists());
    drop(restored_db);
    drop(connection);
    drop(state);
    fs::remove_dir_all(root).unwrap();
}
