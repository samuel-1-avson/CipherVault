use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

#[test]
fn test_diff_secret_comparison_masking_and_revisions() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    // 1. Setup isolated temporary test directory
    let test_dir = std::env::temp_dir().join(format!(
        "ciphervault_diff_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // 2. Initialize vault
    let init_res = Command::new(&bin)
        .args(["init", "--operators", "http://127.0.0.1:8101"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault init");
    assert!(
        init_res.status.success(),
        "init failed: {:?}",
        String::from_utf8_lossy(&init_res.stderr)
    );

    // 3. Create initial secret file and commit Snapshot 1
    let env_content_v1 = "\
DATABASE_URL=postgres://testuser:initial_secret_pwd@localhost:5432/appdb
API_KEY=sk_live_123456789abcdef0
DEBUG=false
";
    fs::write(test_dir.join(".env"), env_content_v1).unwrap();

    let track_res = Command::new(&bin)
        .args(["track", ".env"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to track .env");
    assert!(track_res.status.success());

    let push_res1 = Command::new(&bin)
        .args(["push", "-m", "Snapshot 1 - Initial Secrets"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to push snapshot 1");
    let push_stdout1 = String::from_utf8_lossy(&push_res1.stdout);
    assert!(push_stdout1.contains("Snapshot captured and encrypted locally!"));

    // Extract snapshot 1 ID from push stdout
    // Line format: "Snapshot ID: <64-char-hex>"
    let snap1_id = push_stdout1
        .lines()
        .find(|l| l.contains("Snapshot ID:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .expect("could not extract snapshot 1 id");
    assert_eq!(snap1_id.len(), 64);

    // 4. Modify .env in working tree:
    // - Remove API_KEY
    // - Modify DATABASE_URL
    // - Modify DEBUG
    // - Add NEW_TOKEN
    let env_content_v2 = "\
DATABASE_URL=postgres://testuser:new_rotated_pwd_xyz@localhost:5432/appdb
DEBUG=true
NEW_TOKEN=ghp_secret_access_token_123456789
";
    fs::write(test_dir.join(".env"), env_content_v2).unwrap();

    // 5. Test `ciphervault diff` (Working directory vs Head) with Shoulder-Surfing Defense (Default: Masked)
    let diff_masked = Command::new(&bin)
        .args(["diff"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run ciphervault diff");
    assert!(diff_masked.status.success());
    let diff_masked_str = String::from_utf8_lossy(&diff_masked.stdout);

    // Verify modified and removed keys are shown
    assert!(
        diff_masked_str.contains("DATABASE_URL"),
        "diff should contain DATABASE_URL"
    );
    assert!(
        diff_masked_str.contains("API_KEY"),
        "diff should contain API_KEY"
    );
    assert!(
        diff_masked_str.contains("NEW_TOKEN"),
        "diff should contain NEW_TOKEN"
    );
    assert!(
        diff_masked_str.contains("DEBUG"),
        "diff should contain DEBUG"
    );

    // Shoulder-surfing protection check: Plaintext secrets MUST NOT appear in default diff
    assert!(
        !diff_masked_str.contains("new_rotated_pwd_xyz"),
        "Masked diff must not reveal unmasked DATABASE_URL secret!"
    );
    assert!(
        !diff_masked_str.contains("ghp_secret_access_token_123456789"),
        "Masked diff must not reveal unmasked NEW_TOKEN secret!"
    );
    assert!(
        diff_masked_str.contains("***"),
        "Masked diff must contain masked '***' placeholder"
    );

    // 6. Test `ciphervault diff --reveal`
    let diff_reveal = Command::new(&bin)
        .args(["diff", "--reveal"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run ciphervault diff --reveal");
    assert!(diff_reveal.status.success());
    let diff_reveal_str = String::from_utf8_lossy(&diff_reveal.stdout);

    // With --reveal, the actual plaintext values must be visible
    assert!(
        diff_reveal_str.contains("new_rotated_pwd_xyz"),
        "Revealed diff must show updated secret"
    );
    assert!(
        diff_reveal_str.contains("ghp_secret_access_token_123456789"),
        "Revealed diff must show new secret"
    );
    assert!(
        diff_reveal_str.contains("sk_live_123456789abcdef0"),
        "Revealed diff must show removed secret"
    );

    // 7. Test `ciphervault diff --json`
    let diff_json = Command::new(&bin)
        .args(["diff", "--json"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run ciphervault diff --json");
    assert!(diff_json.status.success());
    let diff_json_str = String::from_utf8_lossy(&diff_json.stdout);

    let parsed_json: serde_json::Value =
        serde_json::from_str(&diff_json_str).expect("diff --json must produce valid JSON output");
    let files = parsed_json["files"]
        .as_array()
        .expect("files array in json");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["file_path"], ".env");
    let entries = files[0]["entries"]
        .as_array()
        .expect("entries array in json");
    assert!(entries.len() >= 4);

    // 8. Test file filter: `ciphervault diff --file nonexistent.txt`
    let diff_filter = Command::new(&bin)
        .args(["diff", "--file", "nonexistent.txt"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run ciphervault diff with filter");
    assert!(diff_filter.status.success());
    let diff_filter_str = String::from_utf8_lossy(&diff_filter.stdout);
    assert!(diff_filter_str.contains("No changes detected"));

    // 9. Push Snapshot 2
    let push_res2 = Command::new(&bin)
        .args(["push", "-m", "Snapshot 2 - Rotated Secrets"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to push snapshot 2");
    let push_stdout2 = String::from_utf8_lossy(&push_res2.stdout);
    let snap2_id = push_stdout2
        .lines()
        .find(|l| l.contains("Snapshot ID:"))
        .and_then(|l| l.split(':').nth(1))
        .map(|s| s.trim().to_string())
        .expect("could not extract snapshot 2 id");
    assert_ne!(snap1_id, snap2_id);

    // 10. Test Snapshot-to-Snapshot diff: `ciphervault diff <snap1_id> <snap2_id> --reveal`
    let diff_snap_to_snap = Command::new(&bin)
        .args(["diff", &snap1_id, &snap2_id, "--reveal"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run snapshot to snapshot diff");
    assert!(diff_snap_to_snap.status.success());
    let snap_diff_str = String::from_utf8_lossy(&diff_snap_to_snap.stdout);
    assert!(snap_diff_str.contains("new_rotated_pwd_xyz"));
    assert!(snap_diff_str.contains("ghp_secret_access_token_123456789"));
    assert!(snap_diff_str.contains("sk_live_123456789abcdef0"));

    // Clean up
    let _ = fs::remove_dir_all(&test_dir);
}

#[test]
fn test_shell_completions_generation() {
    let bin = get_ciphervault_bin();

    // 1. Bash completions
    let bash_out = Command::new(&bin)
        .args(["completions", "bash"])
        .output()
        .expect("failed bash completions");
    assert!(bash_out.status.success());
    let bash_str = String::from_utf8_lossy(&bash_out.stdout);
    assert!(
        bash_str.contains("ciphervault")
            && (bash_str.contains("_ciphervault") || bash_str.contains("complete")),
        "Bash completions should define ciphervault completion functions"
    );

    // 2. PowerShell completions
    let ps_out = Command::new(&bin)
        .args(["completions", "powershell"])
        .output()
        .expect("failed powershell completions");
    assert!(ps_out.status.success());
    let ps_str = String::from_utf8_lossy(&ps_out.stdout);
    assert!(
        ps_str.contains("Register-ArgumentCompleter") || ps_str.contains("ciphervault"),
        "PowerShell completions should register argument completer"
    );

    // 3. Zsh completions
    let zsh_out = Command::new(&bin)
        .args(["completions", "zsh"])
        .output()
        .expect("failed zsh completions");
    assert!(zsh_out.status.success());
    let zsh_str = String::from_utf8_lossy(&zsh_out.stdout);
    assert!(
        zsh_str.contains("#compdef ciphervault") || zsh_str.contains("_ciphervault"),
        "Zsh completions should declare compdef"
    );

    // 4. Fish completions
    let fish_out = Command::new(&bin)
        .args(["completions", "fish"])
        .output()
        .expect("failed fish completions");
    assert!(fish_out.status.success());
    let fish_str = String::from_utf8_lossy(&fish_out.stdout);
    assert!(
        fish_str.contains("complete -c ciphervault"),
        "Fish completions should declare complete -c ciphervault"
    );
}
