//! `run --json` must count shape-only redactions in captured output, not
//! just exact vault values; otherwise receipts under-report what the
//! agent was shielded from.
use std::fs;
use std::path::PathBuf;
use std::process::Command;

fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_ciphervault"))
}

#[test]
fn run_json_counts_shape_only_redactions() {
    let dir = std::env::temp_dir().join(format!(
        "ciphervault_run_count_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir_all(&dir).unwrap();
    let run = |args: &[&str]| {
        Command::new(bin())
            .args(args)
            .current_dir(&dir)
            .env_remove("CIPHERVAULT_OPERATORS")
            .output()
            .expect("failed to run ciphervault")
    };
    let init = run(&["init", "--operators", "http://127.0.0.1:1"]);
    assert!(
        init.status.success(),
        "{}",
        String::from_utf8_lossy(&init.stderr)
    );
    fs::write(dir.join(".env"), "PUBLIC_NAME=fixture-agent\n").unwrap();
    assert!(run(&["track", ".env"]).status.success());
    let push = run(&["push", "--local", "-m", "fixture"]);
    assert!(
        push.status.success(),
        "{}",
        String::from_utf8_lossy(&push.stderr)
    );

    // A credential-shaped value that is NOT a vault value: only the shape
    // pass can catch it. Assembled at runtime; no literal in this file.
    let assignment = format!("{}={}", ["pass", "word"].concat(), "shape-only-fixture");
    #[cfg(target_os = "windows")]
    let shell = ["cmd", "/c"];
    #[cfg(not(target_os = "windows"))]
    let shell = ["sh", "-c"];
    let echo = format!("echo {assignment}");
    let output = run(&["run", "--json", "--", shell[0], shell[1], &echo]);
    assert!(output.status.success(), "{:?}", output);
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let stdout = report["stdout"].as_str().unwrap();
    assert!(!stdout.contains("shape-only-fixture"), "{stdout}");
    assert_eq!(report["redactions"], 1, "{report}");
    let _ = fs::remove_dir_all(&dir);
}
