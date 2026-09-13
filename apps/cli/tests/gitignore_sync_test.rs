use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn get_ciphervault_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

#[test]
fn test_gitignore_smart_secret_detection_and_two_way_sync() {
    let bin = get_ciphervault_bin();
    assert!(
        bin.exists(),
        "ciphervault binary does not exist at {:?}",
        bin
    );

    // Setup isolated temporary test directory
    let test_dir = std::env::temp_dir().join(format!(
        "ciphervault_gitignore_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&test_dir).unwrap();

    // 1. Create a realistic .gitignore with both build bloat and secret files
    let gitignore_content = r#"
# Build and dependency artifacts (MUST BE IGNORED BY CIPHERVAULT)
node_modules/
target/
dist/
build/
*.log
.DS_Store

# Confidential secrets (SHOULD BE DETECTED AND IMPORTED)
.env
.env.production
secrets/*.key
certs/server.pem
"#;
    fs::write(test_dir.join(".gitignore"), gitignore_content).unwrap();

    // 2. Create actual files on disk
    fs::write(
        test_dir.join(".env"),
        "DATABASE_URL=postgres://localhost\nSECRET_KEY=dev123",
    )
    .unwrap();
    fs::write(
        test_dir.join(".env.production"),
        "DATABASE_URL=postgres://prod\nSECRET_KEY=prod456",
    )
    .unwrap();

    fs::create_dir_all(test_dir.join("secrets")).unwrap();
    fs::write(
        test_dir.join("secrets").join("jwt.key"),
        "mock-jwt-private-key-data",
    )
    .unwrap();

    fs::create_dir_all(test_dir.join("certs")).unwrap();
    fs::write(
        test_dir.join("certs").join("server.pem"),
        "mock-tls-certificate",
    )
    .unwrap();

    // Create non-secret/build files on disk that must NOT be tracked
    fs::create_dir_all(test_dir.join("node_modules").join("fake-lib")).unwrap();
    fs::write(
        test_dir
            .join("node_modules")
            .join("fake-lib")
            .join("index.js"),
        "console.log('hi');",
    )
    .unwrap();
    fs::write(test_dir.join("debug.log"), "some error log output").unwrap();

    // 3. Test `ciphervault init --import-gitignore`
    let init_output = Command::new(&bin)
        .args([
            "init",
            "--import-gitignore",
            "--operators",
            "http://127.0.0.1:8101",
        ])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault init --import-gitignore");

    assert!(
        init_output.status.success(),
        "ciphervault init failed: {}",
        String::from_utf8_lossy(&init_output.stderr)
    );

    // 4. Verify tracking status via `ciphervault status`
    let status_output = Command::new(&bin)
        .arg("status")
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault status");

    let status_str = String::from_utf8_lossy(&status_output.stdout);

    // Assert that confidential secrets WERE tracked
    assert!(
        status_str.contains(".env"),
        "Status must contain .env: {}",
        status_str
    );
    assert!(
        status_str.contains(".env.production"),
        "Status must contain .env.production: {}",
        status_str
    );
    assert!(
        status_str.contains("jwt.key"),
        "Status must contain jwt.key: {}",
        status_str
    );
    assert!(
        status_str.contains("server.pem"),
        "Status must contain server.pem: {}",
        status_str
    );

    // Assert that non-secrets / build artifacts were NOT tracked
    assert!(
        !status_str.contains("node_modules"),
        "Status must NOT contain node_modules: {}",
        status_str
    );
    assert!(
        !status_str.contains("fake-lib"),
        "Status must NOT contain fake-lib: {}",
        status_str
    );
    assert!(
        !status_str.contains("debug.log"),
        "Status must NOT contain debug.log: {}",
        status_str
    );

    // 5. Test Two-Way Sync: tracking a new file automatically appends it to .gitignore
    fs::write(
        test_dir.join("oauth_credentials.json"),
        "{\"client_id\":\"1234\"}",
    )
    .unwrap();

    let track_output = Command::new(&bin)
        .args(["track", "oauth_credentials.json"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault track");

    assert!(track_output.status.success());
    let track_stdout = String::from_utf8_lossy(&track_output.stdout);
    assert!(track_stdout.contains("Appended 'oauth_credentials.json' to .gitignore"));

    // Verify .gitignore on disk contains the new file
    let gitignore_after = fs::read_to_string(test_dir.join(".gitignore")).unwrap();
    assert!(
        gitignore_after.contains("oauth_credentials.json"),
        ".gitignore should contain oauth_credentials.json: {}",
        gitignore_after
    );

    // 6. Test `--no-gitignore` flag: track another file without modifying .gitignore
    fs::write(test_dir.join("temp_secret.txt"), "secret").unwrap();

    let track_no_gi = Command::new(&bin)
        .args(["track", "temp_secret.txt", "--no-gitignore"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault track --no-gitignore");

    assert!(track_no_gi.status.success());
    let gitignore_no_gi = fs::read_to_string(test_dir.join(".gitignore")).unwrap();
    assert!(
        !gitignore_no_gi.contains("temp_secret.txt"),
        ".gitignore should NOT contain temp_secret.txt when --no-gitignore is passed"
    );

    // 7. Test on-demand discovery with `ciphervault track --from-gitignore`
    // Add another secret to .gitignore and create on disk
    let mut gi_file = fs::OpenOptions::new()
        .append(true)
        .open(test_dir.join(".gitignore"))
        .unwrap();
    use std::io::Write;
    writeln!(gi_file, "database_seed.key").unwrap();
    fs::write(test_dir.join("database_seed.key"), "seed-key-data").unwrap();

    let track_from_gi = Command::new(&bin)
        .args(["track", "--from-gitignore"])
        .current_dir(&test_dir)
        .output()
        .expect("failed to execute ciphervault track --from-gitignore");

    assert!(
        track_from_gi.status.success(),
        "track --from-gitignore failed: {:?}",
        track_from_gi
    );
    let track_from_gi_out = String::from_utf8_lossy(&track_from_gi.stdout);
    assert!(track_from_gi_out.contains("database_seed.key"));

    // Cleanup test directory
    let _ = fs::remove_dir_all(&test_dir);
}
