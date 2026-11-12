//! `redact --json` must count every rewrite it performs. Shape-only
//! redactions used to report 0, so the Hermes guard and audit receipts
//! said "0 redactions" for text the CLI had in fact changed.
use std::io::Write;
use std::process::{Command, Stdio};

#[test]
fn redact_json_counts_shape_redactions_once() {
    let dir = std::env::temp_dir().join(format!(
        "ciphervault_redact_count_{}_{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    // Assembled at runtime so this source file holds no credential shape.
    let key = ["pass", "word"].concat();
    let input = format!(
        "login {key}=fixture-only-value failed\n\
         retry {key}=another-fixture-value\n\
         already {key}=[REDACTED:DEMO] stays one redaction, not two\n"
    );
    let mut child = Command::new(env!("CARGO_BIN_EXE_ciphervault"))
        .args(["redact", "--json"])
        .current_dir(&dir)
        .env_remove("CIPHERVAULT_OPERATORS")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("failed to run ciphervault redact");
    child
        .stdin
        .take()
        .unwrap()
        .write_all(input.as_bytes())
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    let text = report["text"].as_str().unwrap();
    assert!(
        !text.contains("fixture-only-value") && !text.contains("another-fixture-value"),
        "{text}"
    );
    assert_eq!(report["redactions"], 2, "{report}");
    assert_eq!(report["vault"], false, "{report}");
    let _ = std::fs::remove_dir_all(&dir);
}
