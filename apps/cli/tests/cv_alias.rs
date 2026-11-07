// `cv` and `ciphervault` are the same tool under two names: same version,
// same commands, with help and completions rendered for the invoked name.
use std::process::Command;

fn run(bin: &str, args: &[&str]) -> String {
    let exe = if bin == "cv" {
        env!("CARGO_BIN_EXE_cv")
    } else {
        env!("CARGO_BIN_EXE_ciphervault")
    };
    let output = Command::new(exe)
        .args(args)
        .output()
        .unwrap_or_else(|err| panic!("failed to execute {bin} {args:?}: {err}"));
    assert!(
        output.status.success(),
        "{bin} {args:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("CLI output must be UTF-8")
}

#[test]
fn cv_and_ciphervault_report_the_same_version() {
    let short = run("cv", &["--version"]);
    let long = run("ciphervault", &["--version"]);
    assert!(
        short.starts_with("cv "),
        "unexpected cv version output: {short}"
    );
    assert!(
        long.starts_with("ciphervault "),
        "unexpected ciphervault version output: {long}"
    );
    let short_version = short.split_whitespace().nth(1).expect("cv version number");
    let long_version = long
        .split_whitespace()
        .nth(1)
        .expect("ciphervault version number");
    assert_eq!(short_version, long_version);
}

#[test]
fn help_shows_the_invoked_name() {
    let short = run("cv", &["--help"]);
    assert!(
        short.contains("`cv node setup`"),
        "cv help must show the alias:\n{short}"
    );
    assert!(
        short.contains("`cv` and `ciphervault` are the same tool"),
        "cv help must mention both names:\n{short}"
    );
    let long = run("ciphervault", &["--help"]);
    assert!(
        long.contains("`ciphervault node setup`"),
        "ciphervault help must show the canonical name:\n{long}"
    );
}

#[test]
fn completions_follow_the_invoked_name() {
    let short = run("cv", &["completions", "bash"]);
    assert!(
        short.contains("_cv()"),
        "cv completions must target cv:\n{short}"
    );
    let long = run("ciphervault", &["completions", "bash"]);
    assert!(
        long.contains("_ciphervault()"),
        "ciphervault completions must target ciphervault:\n{long}"
    );
}

#[test]
fn subcommand_help_is_identical_apart_from_name() {
    // Same command tree behind both names: strip the binary name and the
    // outputs must match exactly.
    let normalize = |help: String, bin: &str| help.replace(bin, "<bin>");
    let short = normalize(run("cv", &["init", "--help"]), "cv");
    let long = normalize(run("ciphervault", &["init", "--help"]), "ciphervault");
    assert_eq!(short, long);
}
