use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

#[test]
fn test_run_secret_injection_and_zero_disk_execution() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    // 1. Setup isolated temporary test directory
    let test_dir = std::env::temp_dir().join(format!(
        "ciphervault_run_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
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

    // 3. Create initial secret files on disk
    let env_content = "\
DATABASE_URL=postgres://testuser:testpass@localhost:5432/appdb
APP_SECRET=supersecrettoken123
PORT=9000
";
    fs::write(test_dir.join(".env"), env_content).unwrap();

    let prod_env_content = "\
DATABASE_URL=postgres://produser:prodpass@db.internal:5432/proddb
APP_SECRET=productionsecret789
PROD_FEATURE=enabled
";
    fs::write(test_dir.join(".env.production"), prod_env_content).unwrap();

    // 4. Track confidential secret files and commit snapshot
    let track_res = Command::new(&bin)
        .args(["track", ".env", ".env.production"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to track files");
    assert!(track_res.status.success(), "track failed: {:?}", track_res);

    let push_res = Command::new(&bin)
        .args(["push", "-m", "Credentials snapshot for zero-disk run"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to push snapshot");
    let push_stdout = String::from_utf8_lossy(&push_res.stdout);
    assert!(
        push_stdout.contains("Snapshot captured and encrypted locally!"),
        "push failed to create local snapshot: stdout={}",
        push_stdout
    );

    // 5. Enforce Zero-Disk Environment: Delete secret files from disk!
    fs::remove_file(test_dir.join(".env")).unwrap();
    fs::remove_file(test_dir.join(".env.production")).unwrap();
    assert!(
        !test_dir.join(".env").exists(),
        ".env must not exist on disk"
    );
    assert!(
        !test_dir.join(".env.production").exists(),
        ".env.production must not exist on disk"
    );

    // 6. Test Dry-Run Mode
    let dry_run_res = Command::new(&bin)
        .args(["run", "--dry-run", "--", "echo", "hello"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to run dry-run");
    assert!(dry_run_res.status.success(), "dry-run failed");
    let dry_run_out = String::from_utf8_lossy(&dry_run_res.stdout);
    assert!(dry_run_out.contains("CipherVault Zero-Disk Secret Injection (Dry Run)"));
    assert!(dry_run_out.contains("DATABASE_URL = [REDACTED]"));
    assert!(dry_run_out.contains("APP_SECRET = [REDACTED]"));
    assert!(dry_run_out.contains("PORT = [REDACTED]"));
    assert!(dry_run_out.contains("PROD_FEATURE = [REDACTED]"));
    assert!(dry_run_out.contains("Zero secrets written to disk. Exiting without execution."));

    // Verify zero secrets were written to disk
    assert!(!test_dir.join(".env").exists());
    assert!(!test_dir.join(".env.production").exists());

    // 7. Test Subprocess Secret Injection
    // On Windows, use cmd /c "echo %APP_SECRET%"
    // On Unix, use sh -c 'echo "$APP_SECRET"'
    #[cfg(target_os = "windows")]
    let (shell_cmd, shell_arg) = ("cmd", "/c");
    #[cfg(not(target_os = "windows"))]
    let (shell_cmd, shell_arg) = ("sh", "-c");

    #[cfg(target_os = "windows")]
    let echo_secret_arg = "echo %APP_SECRET%";
    #[cfg(not(target_os = "windows"))]
    let echo_secret_arg = "echo $APP_SECRET";

    let run_res = Command::new(&bin)
        .args(["run", "--", shell_cmd, shell_arg, echo_secret_arg])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault run");

    assert!(
        run_res.status.success(),
        "run command failed: {:?}",
        String::from_utf8_lossy(&run_res.stderr)
    );
    let run_out = String::from_utf8_lossy(&run_res.stdout);
    // .env.production overrides .env, so APP_SECRET should be productionsecret789
    assert!(
        run_out.contains("productionsecret789"),
        "Expected injected APP_SECRET 'productionsecret789', got output: {}",
        run_out
    );

    // Verify zero secrets were written to disk after execution
    assert!(!test_dir.join(".env").exists());
    assert!(!test_dir.join(".env.production").exists());

    // 8. Test Target Secret File Selection with `--env-file .env`
    let target_env_res = Command::new(&bin)
        .args([
            "run",
            "--env-file",
            ".env",
            "--",
            shell_cmd,
            shell_arg,
            echo_secret_arg,
        ])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault run with --env-file");

    assert!(
        target_env_res.status.success(),
        "run with --env-file failed"
    );
    let target_out = String::from_utf8_lossy(&target_env_res.stdout);
    // Specifically targeting .env should inject 'supersecrettoken123'
    assert!(
        target_out.contains("supersecrettoken123"),
        "Expected .env APP_SECRET 'supersecrettoken123', got output: {}",
        target_out
    );

    // 9. Test `--set` Runtime Overrides
    #[cfg(target_os = "windows")]
    let echo_port_arg = "echo %PORT%";
    #[cfg(not(target_os = "windows"))]
    let echo_port_arg = "echo $PORT";

    let override_res = Command::new(&bin)
        .args([
            "run",
            "--set",
            "PORT=4444",
            "--",
            shell_cmd,
            shell_arg,
            echo_port_arg,
        ])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault run with --set");

    assert!(override_res.status.success(), "run with --set failed");
    let override_out = String::from_utf8_lossy(&override_res.stdout);
    assert!(
        override_out.contains("4444"),
        "Expected overridden PORT '4444', got output: {}",
        override_out
    );

    // 10. Test `--quiet` Suppressing Banner
    let quiet_res = Command::new(&bin)
        .args([
            "run",
            "--quiet",
            "--",
            shell_cmd,
            shell_arg,
            echo_secret_arg,
        ])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault run --quiet");

    assert!(quiet_res.status.success());
    let quiet_err = String::from_utf8_lossy(&quiet_res.stderr);
    assert!(
        !quiet_err.contains("[ciphervault] Injected"),
        "Quiet mode must suppress informational banner, but found: {}",
        quiet_err
    );

    // 11. Test Exit Code Propagation
    #[cfg(target_os = "windows")]
    let exit_code_arg = "exit 42";
    #[cfg(not(target_os = "windows"))]
    let exit_code_arg = "exit 42";

    let exit_res = Command::new(&bin)
        .args(["run", "--", shell_cmd, shell_arg, exit_code_arg])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute exit code test");

    assert_eq!(
        exit_res.status.code(),
        Some(42),
        "ciphervault run must propagate child process exit code 42"
    );

    // Cleanup isolated test directory
    let _ = fs::remove_dir_all(&test_dir);
}
