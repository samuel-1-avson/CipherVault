//! Exercise real CLI consumers after epoch rotation using an isolated process
//! environment. No account/keystore state is read from the user's configuration.
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn cli(root: &Path, args: &[&str]) -> Output {
    cli_with_write_setting(root, args, None)
}
fn cli_with_write_setting(root: &Path, args: &[&str], setting: Option<&str>) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_ciphervault"));
    command
        .args(args)
        .current_dir(root)
        .env("CIPHERVAULT_ACCOUNT_DIR", root.join("isolated-account"))
        .env(
            "CIPHERVAULT_KEYSTORE_PATH",
            root.join("isolated-master.key"),
        )
        .env("CIPHERVAULT_MASTER_KEY", "88".repeat(32))
        .env("CIPHERVAULT_OPERATORS", "http://127.0.0.1:1")
        .env_remove("CIPHERVAULT_SCOPE_TOKEN")
        .env_remove("CIPHERVAULT_ACCOUNT_ENDPOINT")
        .env_remove("CIPHERVAULT_OPERATOR_SERVICE_TOKEN")
        .env_remove("CIPHERVAULT_OPERATOR_PINS")
        .env_remove("CIPHERVAULT_DASHBOARD_URL")
        .env_remove("CIPHERVAULT_CHUNK_V2_WRITE")
        .env("NO_COLOR", "1");
    if let Some(value) = setting {
        command.env("CIPHERVAULT_CHUNK_V2_WRITE", value);
    }
    command.output().unwrap()
}
fn succeeds(output: Output) -> String {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}
fn snapshot_id(output: &str) -> String {
    output
        .lines()
        .find(|line| line.contains("Snapshot ID:"))
        .unwrap()
        .split(':')
        .nth(1)
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn historical_restore_diff_and_run_use_each_snapshots_epoch_after_rotation() {
    let root = std::env::temp_dir().join(format!(
        "cv-historical-epochs-{:032x}",
        rand::random::<u128>()
    ));
    fs::create_dir_all(&root).unwrap();
    // macOS temp_dir uses /var, a system alias for /private/var. Pass the
    // canonical fixture path so strict restore sees no symlink ancestors.
    let root = root.canonicalize().unwrap();
    succeeds(cli(&root, &["init", "--operators", "http://127.0.0.1:1"]));
    fs::write(
        root.join(".env"),
        b"SYNTHETIC_EPOCH_SECRET=before_rotation\n",
    )
    .unwrap();
    succeeds(cli(&root, &["track", ".env"]));
    let first = snapshot_id(&succeeds(cli(&root, &["push", "--local"])));
    let rekey = succeeds(cli(&root, &["rekey"]));
    assert!(rekey.contains("epoch 1 -> 2"));
    fs::write(
        root.join(".env"),
        b"SYNTHETIC_EPOCH_SECRET=after_rotation\n",
    )
    .unwrap();
    let second = snapshot_id(&succeeds(cli(&root, &["push", "--local"])));
    assert_ne!(first, second);

    let restored = root.join("historical-restore");
    let preview = succeeds(cli(
        &root,
        &[
            "restore",
            "--snapshot",
            &first,
            "--to",
            restored.to_str().unwrap(),
            "--dry-run",
        ],
    ));
    assert!(preview.contains("create: .env"));
    assert!(
        !restored.exists(),
        "Dry-run must not create the target or staging files"
    );
    fs::create_dir_all(&restored).unwrap();
    fs::write(
        restored.join(".env"),
        b"SYNTHETIC_EPOCH_SECRET=existing_target\n",
    )
    .unwrap();
    let preview = succeeds(cli(
        &root,
        &[
            "restore",
            "--snapshot",
            &first,
            "--to",
            restored.to_str().unwrap(),
            "--dry-run",
        ],
    ));
    assert!(preview.contains("replace: .env"));
    assert_eq!(
        fs::read(restored.join(".env")).unwrap(),
        b"SYNTHETIC_EPOCH_SECRET=existing_target\n"
    );
    assert_eq!(
        fs::read_dir(&restored).unwrap().count(),
        1,
        "Dry-run must not leave staging, journals or locks"
    );
    succeeds(cli(
        &root,
        &[
            "restore",
            "--snapshot",
            &first,
            "--to",
            restored.to_str().unwrap(),
        ],
    ));
    assert_eq!(
        fs::read(restored.join(".env")).unwrap(),
        b"SYNTHETIC_EPOCH_SECRET=before_rotation\n"
    );
    let diff = succeeds(cli(&root, &["diff", &first, &second, "--json", "--reveal"]));
    let diff: serde_json::Value = serde_json::from_str(&diff).unwrap();
    assert_eq!(diff["total_modified"], 1);
    assert!(diff.to_string().contains("before_rotation"));
    assert!(diff.to_string().contains("after_rotation"));

    fs::remove_file(root.join(".env")).unwrap();
    #[cfg(windows)]
    let child = ["cmd", "/c", "echo %SYNTHETIC_EPOCH_SECRET%"];
    #[cfg(not(windows))]
    let child = ["sh", "-c", "printf '%s' \"$SYNTHETIC_EPOCH_SECRET\""];
    let mut args = vec![
        "run",
        "--snapshot",
        first.as_str(),
        "--legacy",
        "--quiet",
        "--",
    ];
    args.extend(child);
    let output = succeeds(cli(&root, &args));
    assert!(output.contains("before_rotation"));
    assert!(!output.contains("after_rotation"));
    assert!(
        !root.join(".env").exists(),
        "Historical run must not materialize plaintext files"
    );
    fs::remove_dir_all(root).unwrap();
}

fn json(output: Output) -> serde_json::Value {
    serde_json::from_str(&succeeds(output)).unwrap()
}

#[test]
fn json_history_and_restore_preview_are_bounded_read_only_contracts() {
    let root = std::env::temp_dir().join(format!(
        "cv-history-preview-{:032x}",
        rand::random::<u128>()
    ));
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    succeeds(cli(&root, &["init", "--operators", "http://127.0.0.1:1"]));
    let empty = json(cli(&root, &["history", "--json"]));
    assert_eq!(empty["total"], 0);
    assert!(empty["snapshots"].as_array().unwrap().is_empty());

    fs::write(
        root.join(".env"),
        b"SYNTHETIC_PREVIEW_SECRET=before_preview\n",
    )
    .unwrap();
    succeeds(cli(&root, &["track", ".env"]));
    let first_logical = snapshot_id(&succeeds(cli(&root, &["push", "--local"])));
    fs::write(
        root.join(".env"),
        b"SYNTHETIC_PREVIEW_SECRET=after_preview\n",
    )
    .unwrap();
    succeeds(cli(&root, &["push", "--local"]));

    let newest = json(cli(&root, &["history", "--json", "--limit", "1"]));
    assert_eq!(newest["total"], 2);
    assert_eq!(newest["returned"], 1);
    assert_eq!(newest["truncated"], true);
    assert_eq!(newest["snapshots"][0]["is_active_head"], true);
    let status = json(cli(&root, &["status", "--json"]));
    assert_eq!(
        newest["snapshots"][0]["snapshot_id"],
        status["active_head_hex"]
    );
    assert!(
        status.get("watcher_health").is_none(),
        "plain status is unchanged"
    );

    let all = json(cli(&root, &["history", "--json"]));
    let older = &all["snapshots"][1];
    assert_eq!(older["logical_id"], first_logical.as_str());
    assert_eq!(older["is_active_head"], false);
    let older_id = older["snapshot_id"].as_str().unwrap().to_string();
    let text = succeeds(cli(&root, &["history"]));
    assert!(text.contains("[1] Snapshot:") && text.contains(&first_logical));

    for reference in [older_id.as_str(), first_logical.as_str()] {
        let preview = json(cli(
            &root,
            &["restore", "--snapshot", reference, "--dry-run", "--json"],
        ));
        assert_eq!(preview["success"], true);
        assert_eq!(preview["snapshot_id"], older_id.as_str());
        assert_eq!(preview["destination"], "workspace");
        assert_eq!(preview["verification"]["status"], "passed");
        assert_eq!(
            preview["verification"]["checks"].as_array().unwrap().len(),
            6
        );
        assert_eq!(preview["files"][0]["path"], ".env");
        assert_eq!(preview["files"][0]["action"], "replace");
        assert_eq!(preview["counts"]["replace"], 1);
        assert_eq!(preview["restore_requires_force"], false);
        let rendered = preview.to_string();
        assert!(!rendered.contains("before_preview") && !rendered.contains("after_preview"));
    }
    assert_eq!(
        fs::read(root.join(".env")).unwrap(),
        b"SYNTHETIC_PREVIEW_SECRET=after_preview\n"
    );
    assert!(!root.join(".ciphervault-restore").exists());
    assert!(!root.join(".ciphervault-restore.lock").exists());

    for (reference, code) in [
        ("f".repeat(64), "snapshot_not_found"),
        ("not-hex".to_string(), "invalid_snapshot_id"),
    ] {
        let refused = cli(
            &root,
            &["restore", "--snapshot", &reference, "--dry-run", "--json"],
        );
        assert_eq!(refused.status.code(), Some(3));
        let report: serde_json::Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(report["success"], false);
        assert_eq!(report["error_code"], code);
    }

    assert!(!cli(&root, &["restore", "--json"]).status.success());
    assert!(!cli(&root, &["history", "--limit", "5"]).status.success());
    for bad in ["0", "101"] {
        assert!(!cli(&root, &["history", "--json", "--limit", bad])
            .status
            .success());
    }
    let elsewhere = std::env::temp_dir().join(format!(
        "cv-history-vaultless-{:032x}",
        rand::random::<u128>()
    ));
    fs::create_dir_all(&elsewhere).unwrap();
    let vaultless = json(cli(&elsewhere, &["history", "--json"]));
    assert_eq!(vaultless["vault"], false);
    fs::remove_dir_all(elsewhere).unwrap();
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn writer_gate_is_fail_safe_in_real_cli_capture() {
    let root = std::env::temp_dir().join(format!("cv-writer-gate-{:032x}", rand::random::<u128>()));
    fs::create_dir_all(&root).unwrap();
    let root = root.canonicalize().unwrap();
    succeeds(cli(&root, &["init", "--operators", "http://127.0.0.1:1"]));
    fs::write(root.join(".env"), b"SYNTHETIC_WRITE_GATE=test\n").unwrap();
    succeeds(cli(&root, &["track", ".env"]));
    let invalid = cli_with_write_setting(&root, &["push", "--local"], Some("true"));
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("CIPHERVAULT_CHUNK_V2_WRITE"));
    let store = ciphervault_local_store::LocalVaultStore::open_read_only(
        root.join(".ciphervault/vault.db"),
    )
    .unwrap();
    assert!(store.list_snapshots().unwrap().is_empty());
    assert!(store.list_pending_uploads().unwrap().is_empty());
    // The child encrypts its device key with the harness's explicit portable
    // master key. Inspect through that same child environment: the parent
    // deliberately retains its own keystore and must not decrypt child keys.
    let status: serde_json::Value =
        serde_json::from_str(&succeeds(cli(&root, &["status", "--json"]))).unwrap();
    assert_eq!(status["device_counter"], 0);
    let versions = || {
        let head = store.get_active_head().unwrap().unwrap();
        let cid = head.snapshot_id.as_slice().try_into().unwrap();
        let set = store.get_recovery_set(&cid).unwrap();
        let chunks: Vec<[u8; 32]> = set
            .closure
            .chunk_cids
            .iter()
            .map(|cid| cid.as_slice().try_into().unwrap())
            .collect();
        store
            .get_chunks(&chunks)
            .unwrap()
            .iter()
            .map(|chunk| chunk.version)
            .collect::<Vec<_>>()
    };
    succeeds(cli(&root, &["push", "--local"]));
    assert!(versions().iter().all(|version| *version == 2));
    succeeds(cli_with_write_setting(
        &root,
        &["push", "--local"],
        Some("0"),
    ));
    assert!(versions().iter().all(|version| *version == 1));
    drop(store);
    fs::remove_dir_all(root).unwrap();
}
