//! Self-update from GitHub Releases: check the latest release, download the
//! platform archive, verify it against SHA256SUMS, and install it.
//!
//! The CLI (`ciphervault update`) and the TUI update popup share this engine;
//! only the progress reporting differs (stdout vs. status line).

use anyhow::{bail, Context, Result};
use reqwest::Client as HttpClient;
use sha2::{Digest, Sha256};
use std::fs;
use std::time::Duration;

/// Release version for update comparison: numeric core plus an optional
/// prerelease suffix (`v1.0.7-beta.1` -> core (1,0,7), pre "beta.1").
/// Splitting the suffix out matters: parsing "7-beta" as a number yields 0,
/// which previously made every prerelease tag compare older than any release.
struct ReleaseVersion {
    core: (u64, u64, u64),
    pre: Option<String>,
}

impl ReleaseVersion {
    fn parse(tag: &str) -> Self {
        let tag = tag.trim().trim_start_matches('v');
        let (core_part, pre_part) = match tag.split_once('-') {
            Some((core, pre)) => (core, Some(pre.to_string())),
            None => (tag, None),
        };
        let mut nums = core_part
            .split('.')
            .map(|part| part.trim().parse::<u64>().unwrap_or(0));
        Self {
            core: (
                nums.next().unwrap_or(0),
                nums.next().unwrap_or(0),
                nums.next().unwrap_or(0),
            ),
            pre: pre_part.filter(|part| !part.is_empty()),
        }
    }

    /// True when `self` is a newer release than `other`, following semver
    /// precedence: a higher core wins; for equal cores a final release beats
    /// any prerelease, and prereleases compare identifier by identifier.
    fn is_newer_than(&self, other: &Self) -> bool {
        if self.core != other.core {
            return self.core > other.core;
        }
        match (&self.pre, &other.pre) {
            (None, None) => false,
            (None, Some(_)) => true,
            (Some(_), None) => false,
            (Some(a), Some(b)) => compare_pre_release(a, b) == std::cmp::Ordering::Greater,
        }
    }
}

/// Compares dot-separated prerelease identifiers with numeric-aware ordering
/// (`beta.2` < `beta.10`); numeric identifiers sort below alphanumeric ones.
fn compare_pre_release(a: &str, b: &str) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    let mut a_parts = a.split('.');
    let mut b_parts = b.split('.');
    loop {
        match (a_parts.next(), b_parts.next()) {
            (None, None) => return Ordering::Equal,
            (None, Some(_)) => return Ordering::Less,
            (Some(_), None) => return Ordering::Greater,
            (Some(x), Some(y)) => {
                let ord = match (x.parse::<u64>(), y.parse::<u64>()) {
                    (Ok(xn), Ok(yn)) => xn.cmp(&yn),
                    (Ok(_), Err(_)) => Ordering::Less,
                    (Err(_), Ok(_)) => Ordering::Greater,
                    (Err(_), Err(_)) => x.cmp(y),
                };
                if ord != Ordering::Equal {
                    return ord;
                }
            }
        }
    }
}

/// Release target triple + archive suffix for an (os, arch, musl) tuple.
/// musl builds must resolve to the musl target: installing the glibc binary
/// on a musl-only system would leave a non-executable CLI behind.
fn release_target_for(os: &str, arch: &str, musl: bool) -> Option<(&'static str, &'static str)> {
    match (os, arch) {
        ("windows", "x86_64") => Some(("x86_64-pc-windows-msvc", "zip")),
        ("linux", "x86_64") if musl => Some(("x86_64-unknown-linux-musl", "tar.gz")),
        ("linux", "x86_64") => Some(("x86_64-unknown-linux-gnu", "tar.gz")),
        ("linux", "aarch64") => Some(("aarch64-unknown-linux-gnu", "tar.gz")),
        ("macos", "x86_64") => Some(("x86_64-apple-darwin", "tar.gz")),
        ("macos", "aarch64") => Some(("aarch64-apple-darwin", "tar.gz")),
        _ => None,
    }
}

fn release_target() -> Option<(&'static str, &'static str)> {
    release_target_for(
        std::env::consts::OS,
        std::env::consts::ARCH,
        cfg!(target_env = "musl"),
    )
}

/// Looks up one file's digest in `sha256sum` output (`<hex>  <name>`).
fn find_checksum(sums: &str, name: &str) -> Option<String> {
    sums.lines().find_map(|line| {
        let mut fields = line.split_whitespace();
        let digest = fields.next()?;
        let entry = fields.next()?.trim_start_matches('*');
        (entry == name).then(|| digest.to_ascii_lowercase())
    })
}

/// Effectively crate-confined (`commands` is `pub(crate)`); declared `pub`
/// so the `pub` TUI app state can hold it.
pub struct PendingUpdate {
    pub tag: String,
    pub(crate) target: &'static str,
    pub(crate) archive_suffix: &'static str,
}

pub(crate) struct ReleaseCheck {
    pub current: String,
    pub latest_tag: String,
    pub pending: Option<PendingUpdate>,
}

/// Token for private-repo release downloads, explicit var first. Never logged.
fn github_token() -> Option<String> {
    ["CIPHERVAULT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]
        .into_iter()
        .filter_map(|name| std::env::var(name).ok())
        .map(|value| value.trim().to_string())
        .find(|value| !value.is_empty())
}

fn authed_request(client: &HttpClient, url: String) -> reqwest::RequestBuilder {
    let mut request = client.get(url);
    if let Some(token) = github_token() {
        request = request.header("Authorization", format!("Bearer {token}"));
    }
    request
}

const PRIVATE_REPO_HINT: &str = "if the repo is private, set CIPHERVAULT_GITHUB_TOKEN";

/// Queries the latest GitHub release and reports whether it is newer than
/// this binary. Network errors propagate; "already latest" is `Ok` with no
/// pending update.
pub(crate) async fn check_for_updates() -> Result<ReleaseCheck> {
    let (target, archive_suffix) = match release_target() {
        Some(pair) => pair,
        None => bail!(
            "No published CipherVault release for {}/{}",
            std::env::consts::OS,
            std::env::consts::ARCH
        ),
    };
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let release: serde_json::Value = authed_request(
        &client,
        "https://api.github.com/repos/samuel-1-avson/CipherVault/releases/latest".to_string(),
    )
    .header("Accept", "application/vnd.github+json")
    .send()
    .await
    .context("checking the CipherVault release feed")?
    .error_for_status()
    .with_context(|| {
        format!("GitHub did not return the latest CipherVault release ({PRIVATE_REPO_HINT})")
    })?
    .json()
    .await
    .context("decoding the CipherVault release feed")?;
    let tag = release
        .get("tag_name")
        .and_then(serde_json::Value::as_str)
        .context("latest release did not include a tag")?;
    let current = env!("CARGO_PKG_VERSION");
    let current_version = ReleaseVersion::parse(current);
    let latest_version = ReleaseVersion::parse(tag);
    let pending = latest_version
        .is_newer_than(&current_version)
        .then(|| PendingUpdate {
            tag: tag.to_string(),
            target,
            archive_suffix,
        });
    Ok(ReleaseCheck {
        current: current.to_string(),
        latest_tag: tag.to_string(),
        pending,
    })
}

// Each variant is constructed on one platform family only.
#[allow(dead_code)]
pub(crate) enum InstallOutcome {
    /// Binary swapped in place (Unix).
    Installed,
    /// Windows helper will swap the binary after this process exits.
    PendingRestart,
}

/// Downloads, checksum-verifies, extracts, and installs `pending`,
/// reporting human-readable stages through `on_stage`.
pub(crate) async fn apply_update(
    pending: &PendingUpdate,
    mut on_stage: impl FnMut(&str),
) -> Result<InstallOutcome> {
    let client = HttpClient::builder()
        .timeout(Duration::from_secs(20))
        .user_agent(concat!("ciphervault/", env!("CARGO_PKG_VERSION")))
        .build()?;
    let tag = &pending.tag;
    let archive_name = format!(
        "ciphervault-{tag}-{}.{}",
        pending.target, pending.archive_suffix
    );
    let sums_name = "SHA256SUMS.txt";
    let base_url = format!("https://github.com/samuel-1-avson/CipherVault/releases/download/{tag}");
    on_stage(&format!("Downloading {archive_name}..."));
    let archive = authed_request(&client, format!("{base_url}/{archive_name}"))
        .send()
        .await
        .context("downloading the latest CipherVault archive")?
        .error_for_status()
        .with_context(|| {
            format!("latest CipherVault archive is unavailable ({PRIVATE_REPO_HINT})")
        })?
        .bytes()
        .await
        .context("reading the latest CipherVault archive")?;
    on_stage("Downloading checksums...");
    let sums = authed_request(&client, format!("{base_url}/{sums_name}"))
        .send()
        .await
        .context("downloading the CipherVault release checksum")?
        .error_for_status()
        .with_context(|| {
            format!("latest CipherVault checksum is unavailable ({PRIVATE_REPO_HINT})")
        })?
        .text()
        .await
        .context("reading the CipherVault release checksum")?;
    on_stage("Verifying checksum...");
    let expected = find_checksum(&sums, &archive_name)
        .context("release checksum does not contain the selected archive")?;
    let actual = hex::encode(Sha256::digest(&archive));
    if expected != actual {
        bail!("release checksum mismatch for {archive_name}");
    }

    on_stage("Extracting...");
    let temp_root = std::env::temp_dir().join(format!(
        "ciphervault-update-{}-{}",
        std::process::id(),
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or_default()
    ));
    fs::create_dir_all(&temp_root)?;
    let archive_path = temp_root.join(&archive_name);
    fs::write(&archive_path, &archive)?;
    let extract_dir = temp_root.join("extract");
    fs::create_dir_all(&extract_dir)?;
    #[cfg(windows)]
    {
        let status = std::process::Command::new("powershell.exe")
            .args([
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "Expand-Archive -LiteralPath $args[0] -DestinationPath $args[1] -Force",
                &archive_path.to_string_lossy(),
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .context("extracting the Windows release archive")?;
        if !status.success() {
            bail!("Windows release archive extraction failed");
        }
    }
    #[cfg(not(windows))]
    {
        let status = std::process::Command::new("tar")
            .args([
                "-xzf",
                &archive_path.to_string_lossy(),
                "-C",
                &extract_dir.to_string_lossy(),
            ])
            .status()
            .context("extracting the release archive")?;
        if !status.success() {
            bail!("release archive extraction failed");
        }
    }
    let binary_name = if cfg!(windows) {
        "ciphervault.exe"
    } else {
        "ciphervault"
    };
    let extracted_binary = walkdir::WalkDir::new(&extract_dir)
        .into_iter()
        .filter_map(Result::ok)
        .find(|entry| entry.file_type().is_file() && entry.file_name() == binary_name)
        .map(|entry| entry.into_path())
        .context("release archive did not contain the CipherVault CLI")?;
    on_stage("Installing...");
    let current_exe = std::env::current_exe().context("locating the running CipherVault CLI")?;
    #[cfg(windows)]
    let outcome = {
        let replacement = current_exe.with_extension("exe.new");
        fs::copy(&extracted_binary, &replacement)?;
        let script = current_exe.with_extension("update.cmd");
        let script_body = format!(
            "@echo off\r\n:wait\r\nmove /Y \"{}\" \"{}\" >nul 2>&1\r\nif errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait)\r\ndel \"%~f0\"\r\n",
            replacement.display(),
            current_exe.display()
        );
        fs::write(&script, script_body)?;
        std::process::Command::new("cmd.exe")
            .args(["/C", "start", "", "/B", &script.to_string_lossy()])
            .spawn()
            .context("starting the Windows update helper")?;
        InstallOutcome::PendingRestart
    };
    #[cfg(not(windows))]
    let outcome = {
        let replacement = current_exe.with_extension("new");
        fs::copy(&extracted_binary, &replacement)?;
        fs::rename(replacement, current_exe)?;
        InstallOutcome::Installed
    };
    let _ = fs::remove_dir_all(temp_root);
    Ok(outcome)
}

pub(crate) async fn cmd_update(check_only: bool) -> Result<()> {
    let check = check_for_updates().await?;
    println!(
        "Current CipherVault: {}; latest release: {}",
        check.current, check.latest_tag
    );
    let Some(pending) = check.pending else {
        println!("Already at or ahead of the latest published release.");
        return Ok(());
    };
    if check_only {
        println!("Run `ciphervault update` to install the verified release.");
        return Ok(());
    }
    match apply_update(&pending, |_| {}).await? {
        InstallOutcome::Installed => {
            println!("Verified and installed CipherVault {}.", pending.tag);
        }
        InstallOutcome::PendingRestart => {
            println!(
                "Verified {}; the new CLI will be installed after this process exits.",
                pending.tag
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod update_version_tests {
    use super::*;

    fn offers_update(current: &str, latest_tag: &str) -> bool {
        ReleaseVersion::parse(latest_tag).is_newer_than(&ReleaseVersion::parse(current))
    }

    #[test]
    fn prerelease_tag_with_higher_core_is_offered() {
        // Regression: "7-beta" used to parse as 0, so v1.0.7-beta.1 compared
        // older than 1.0.6 and no user was ever offered the beta.
        assert!(offers_update("1.0.6", "v1.0.7-beta.1"));
        assert_eq!(ReleaseVersion::parse("v1.0.7-beta.1").core, (1, 0, 7));
    }

    #[test]
    fn same_prerelease_is_not_offered() {
        assert!(!offers_update("1.0.7-beta.1", "v1.0.7-beta.1"));
    }

    #[test]
    fn prerelease_moves_forward_within_pre_suffix() {
        assert!(offers_update("1.0.7-beta.1", "v1.0.7-beta.2"));
        // Numeric identifiers compare numerically, not lexicographically.
        assert!(offers_update("1.0.7-beta.2", "v1.0.7-beta.10"));
        assert!(!offers_update("1.0.7-beta.10", "v1.0.7-beta.2"));
    }

    #[test]
    fn final_release_beats_its_prerelease_but_never_downgrades() {
        assert!(offers_update("1.0.7-beta.1", "v1.0.7"));
        assert!(!offers_update("1.0.7", "v1.0.7-beta.1"));
    }

    #[test]
    fn plain_release_comparison_still_works() {
        assert!(offers_update("1.0.6", "v1.0.7"));
        assert!(!offers_update("1.0.6", "v1.0.6"));
        assert!(!offers_update("1.0.7", "v1.0.6"));
    }

    #[test]
    fn release_targets_cover_packaged_platforms() {
        assert_eq!(
            release_target_for("windows", "x86_64", false),
            Some(("x86_64-pc-windows-msvc", "zip"))
        );
        assert_eq!(
            release_target_for("linux", "x86_64", false),
            Some(("x86_64-unknown-linux-gnu", "tar.gz"))
        );
        // musl builds must resolve to the musl target, never glibc.
        assert_eq!(
            release_target_for("linux", "x86_64", true),
            Some(("x86_64-unknown-linux-musl", "tar.gz"))
        );
        assert_eq!(
            release_target_for("linux", "aarch64", false),
            Some(("aarch64-unknown-linux-gnu", "tar.gz"))
        );
        assert_eq!(
            release_target_for("macos", "x86_64", false),
            Some(("x86_64-apple-darwin", "tar.gz"))
        );
        assert_eq!(
            release_target_for("macos", "aarch64", false),
            Some(("aarch64-apple-darwin", "tar.gz"))
        );
        assert_eq!(release_target_for("freebsd", "x86_64", false), None);
    }

    #[test]
    fn checksum_lookup_matches_gnu_sha256sum_format() {
        let digest = "ab".repeat(32);
        let sums = format!("{digest}  ciphervault-v9-x86_64-pc-windows-msvc.zip\n");
        assert_eq!(
            find_checksum(&sums, "ciphervault-v9-x86_64-pc-windows-msvc.zip"),
            Some(digest)
        );
        assert_eq!(find_checksum(&sums, "other.zip"), None);
        assert_eq!(find_checksum("not a sums file", "other.zip"), None);
    }

    #[test]
    fn github_token_prefers_explicit_var_and_trims() {
        const NAMES: [&str; 3] = ["CIPHERVAULT_GITHUB_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"];
        let saved: Vec<(String, Option<String>)> = NAMES
            .iter()
            .map(|n| (n.to_string(), std::env::var(n).ok()))
            .collect();
        for name in NAMES {
            std::env::remove_var(name);
        }
        assert_eq!(github_token(), None);
        std::env::set_var("GITHUB_TOKEN", "fallback");
        assert_eq!(github_token().as_deref(), Some("fallback"));
        std::env::set_var("GH_TOKEN", "middle");
        assert_eq!(github_token().as_deref(), Some("middle"));
        std::env::set_var("CIPHERVAULT_GITHUB_TOKEN", "  explicit  ");
        assert_eq!(github_token().as_deref(), Some("explicit"));
        for (name, value) in saved {
            match value {
                Some(v) => std::env::set_var(name, v),
                None => std::env::remove_var(name),
            }
        }
    }
}
