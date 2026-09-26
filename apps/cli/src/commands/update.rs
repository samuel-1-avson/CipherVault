//! Self-update from GitHub Releases: check the latest release, download the
//! platform archive, verify it against SHA256SUMS, and install it.
//!
//! The CLI (`ciphervault update`) and the TUI update popup share this engine;
//! only the progress reporting differs (stdout vs. status line).

use anyhow::{bail, Context, Result};
use reqwest::Client as HttpClient;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// Release version for update comparison: numeric core plus an optional
/// prerelease suffix (`v1.0.7-beta.1` -> core (1,0,7), pre "beta.1").
/// Splitting the suffix out matters: parsing "7-beta" as a number yields 0,
/// which previously made every prerelease tag compare older than any release.
pub(crate) struct ReleaseVersion {
    core: (u64, u64, u64),
    pre: Option<String>,
}

impl ReleaseVersion {
    /// Numeric core of a tag/version string for cross-binary comparison.
    pub(crate) fn core_of(tag: &str) -> (u64, u64, u64) {
        Self::parse(tag).core
    }

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

/// Finds a release asset's numeric id by file name in `GET release` JSON.
fn find_asset_id(release: &serde_json::Value, name: &str) -> Option<u64> {
    release
        .get("assets")?
        .as_array()?
        .iter()
        .filter(|asset| asset.get("name").and_then(serde_json::Value::as_str) == Some(name))
        .filter_map(|asset| asset.get("id").and_then(serde_json::Value::as_u64))
        .next()
}

/// Companion binaries shipped in every release archive next to the CLI.
/// `ciphervault update` refreshes all of these, so the operator daemon a
/// wizard-run node uses can never silently lag the CLI (the stale-operator
/// trap: old daemon, missing flags, confusing 404s).
const COMPANION_BINARY_STEMS: &[&str] = &[
    "ciphervault-operator",
    "ciphervault-agent",
    "ciphervault-maintenance",
];

fn platform_binary_name(stem: &str) -> String {
    if cfg!(windows) {
        format!("{stem}.exe")
    } else {
        stem.to_string()
    }
}

/// Locates one binary by file name anywhere under an extracted release tree
/// Nesting is `<pkg>/bin/`; returns `None` unless exactly one matches.
fn find_binary_in(dir: &Path, name: &str) -> Option<PathBuf> {
    let mut matches = walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.file_type().is_file() && entry.file_name() == name)
        .map(walkdir::DirEntry::into_path);
    let first = matches.next()?;
    if matches.next().is_some() {
        return None;
    }
    Some(first)
}

/// Builds the post-exit swap script: the CLI move waits unbounded (this
/// process is exiting, so its lock always clears), while each companion
/// move retries for ~60 s and then skips — a running node daemon holds
/// its own .exe locked, and the update must not hang forever on it.
#[allow(dead_code)] // Windows install path only; exercised by tests everywhere.
fn windows_update_script(
    cli_staged: &Path,
    cli_live: &Path,
    companions: &[(PathBuf, PathBuf)],
) -> String {
    let mut script = String::from("@echo off\r\nsetlocal EnableDelayedExpansion\r\n");
    script.push_str(":wait_cli\r\n");
    script.push_str(&format!(
        "move /Y \"{}\" \"{}\" >nul 2>&1\r\n",
        cli_staged.display(),
        cli_live.display()
    ));
    script.push_str("if errorlevel 1 (timeout /t 1 /nobreak >nul & goto wait_cli)\r\n");
    for (index, (staged, live)) in companions.iter().enumerate() {
        script.push_str(&format!("set tries{index}=60\r\n"));
        script.push_str(&format!(":wait_{index}\r\n"));
        script.push_str(&format!(
            "move /Y \"{}\" \"{}\" >nul 2>&1\r\n",
            staged.display(),
            live.display()
        ));
        script.push_str(&format!(
            "if errorlevel 1 (set /a tries{index}-=1 >nul & if !tries{index}! GTR 0 (timeout /t 1 /nobreak >nul & goto wait_{index}))\r\n"
        ));
    }
    script.push_str("del \"%~f0\"\r\n");
    script
}

/// True when the extracted tree holds only plain files and dirs (no
/// symlinks): release archives never legitimately contain them, and a
/// symlink inside the tree could redirect reads outside it.
fn extracted_tree_has_no_symlinks(dir: &Path) -> bool {
    walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(Result::ok)
        .all(|entry| !entry.file_type().is_symlink())
}

/// True when a tar listing contains only paths confined under the
/// destination: no absolute paths, no parent traversal.
#[cfg_attr(windows, allow(dead_code))] // non-Windows extract path; tests call it everywhere
fn tar_listing_is_confined(listing: &str) -> bool {
    !listing.lines().any(|entry| {
        let entry = entry.trim();
        entry.starts_with('/') || entry.split('/').any(|component| component == "..")
    })
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
    // Assets download through the API asset endpoint (octet-stream): the
    // browser-download redirector does not honor tokens on private repos.
    let release: serde_json::Value = authed_request(
        &client,
        format!("https://api.github.com/repos/samuel-1-avson/CipherVault/releases/tags/{tag}"),
    )
    .header("Accept", "application/vnd.github+json")
    .send()
    .await
    .context("reading the CipherVault release")?
    .error_for_status()
    .with_context(|| format!("GitHub did not return release {tag} ({PRIVATE_REPO_HINT})"))?
    .json()
    .await
    .context("decoding the CipherVault release")?;
    let asset_url = |name: &str| {
        find_asset_id(&release, name).map(|id| {
            format!("https://api.github.com/repos/samuel-1-avson/CipherVault/releases/assets/{id}")
        })
    };
    let archive_url =
        asset_url(&archive_name).with_context(|| format!("release {tag} has no {archive_name}"))?;
    let sums_url =
        asset_url(sums_name).with_context(|| format!("release {tag} has no {sums_name}"))?;
    on_stage(&format!("Downloading {archive_name}..."));
    let archive = authed_request(&client, archive_url)
        .header("Accept", "application/octet-stream")
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
    let sums = authed_request(&client, sums_url)
        .header("Accept", "application/octet-stream")
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
        // Reject archives with absolute paths or parent traversal before
        // extracting: a tampered release must not write outside `extract_dir`.
        let listing = std::process::Command::new("tar")
            .arg("-tzf")
            .arg(&archive_path)
            .output()
            .context("listing the release archive")?;
        if !listing.status.success() {
            bail!("release archive listing failed");
        }
        if !tar_listing_is_confined(&String::from_utf8_lossy(&listing.stdout)) {
            bail!("release archive contains absolute or parent-relative paths");
        }
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
    if !extracted_tree_has_no_symlinks(&extract_dir) {
        bail!("release archive contains symlinks");
    }
    let cli_name = platform_binary_name("ciphervault");
    let extracted_cli = find_binary_in(&extract_dir, &cli_name)
        .context("release archive must contain exactly one CipherVault CLI")?;
    let mut companions: Vec<(String, PathBuf)> = Vec::new();
    for stem in COMPANION_BINARY_STEMS {
        let name = platform_binary_name(stem);
        match find_binary_in(&extract_dir, &name) {
            Some(path) => companions.push((name, path)),
            None => on_stage(&format!(
                "{name} is not in this release; keeping the installed copy."
            )),
        }
    }
    on_stage("Installing...");
    let current_exe = std::env::current_exe().context("locating the running CipherVault CLI")?;
    let bin_dir = current_exe
        .parent()
        .context("locating the CipherVault install dir")?
        .to_path_buf();
    #[cfg(windows)]
    let outcome = {
        let cli_staged = current_exe.with_extension("exe.new");
        fs::copy(&extracted_cli, &cli_staged)?;
        let mut moves: Vec<(PathBuf, PathBuf)> = Vec::new();
        for (name, src) in &companions {
            let live = bin_dir.join(name);
            let staged = live.with_extension("exe.new");
            fs::copy(src, &staged)?;
            moves.push((staged, live));
        }
        let script = current_exe.with_extension("update.cmd");
        fs::write(
            &script,
            windows_update_script(&cli_staged, &current_exe, &moves),
        )?;
        std::process::Command::new("cmd.exe")
            .args(["/C", "start", "", "/B", &script.to_string_lossy()])
            .spawn()
            .context("starting the Windows update helper")?;
        InstallOutcome::PendingRestart
    };
    #[cfg(not(windows))]
    let outcome = {
        let staged = current_exe.with_extension("new");
        fs::copy(&extracted_cli, &staged)?;
        fs::rename(&staged, &current_exe)?;
        for (name, src) in &companions {
            let live = bin_dir.join(name);
            let staged = live.with_extension("new");
            fs::copy(src, &staged)?;
            fs::rename(&staged, &live)?;
        }
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
            println!(
                "Verified and installed CipherVault {} (CLI plus operator, agent, and maintenance binaries).",
                pending.tag
            );
            println!(
                "Restart any running node (`ciphervault node stop` / `node start`) to use the new operator binary."
            );
        }
        InstallOutcome::PendingRestart => {
            println!(
                "Verified {}; the new binaries will be installed after this process exits.",
                pending.tag
            );
            println!(
                "If a node daemon is running, restart it afterwards (`ciphervault node stop` / `node start`)."
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
    fn extracted_tree_accepts_plain_files() {
        let root = std::env::temp_dir().join(format!("cv_nosym_plain_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("real"), b"x").unwrap();
        assert!(extracted_tree_has_no_symlinks(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[cfg(not(windows))]
    #[test]
    fn extracted_tree_rejects_symlinks() {
        let root = std::env::temp_dir().join(format!("cv_nosym_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("real"), b"x").unwrap();
        assert!(extracted_tree_has_no_symlinks(&root));
        std::os::unix::fs::symlink("real", root.join("link")).unwrap();
        assert!(!extracted_tree_has_no_symlinks(&root));
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn tar_listing_rejects_escape_paths() {
        assert!(tar_listing_is_confined("pkg/bin/ciphervault\npkg/bin/op\n"));
        assert!(tar_listing_is_confined("a..b\n...\n"));
        assert!(!tar_listing_is_confined("pkg/../../evil\n"));
        assert!(!tar_listing_is_confined("/abs/path\n"));
        assert!(!tar_listing_is_confined("a/b/../../../x\n"));
    }

    #[test]
    fn find_binary_in_resolves_only_unique_matches() {
        let root = std::env::temp_dir().join(format!("cv_findbin_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("pkg/bin")).unwrap();
        std::fs::write(root.join("pkg/bin/ciphervault"), b"x").unwrap();
        assert!(find_binary_in(&root, "ciphervault").is_some());
        assert!(find_binary_in(&root, "missing").is_none());
        std::fs::create_dir_all(root.join("other")).unwrap();
        std::fs::write(root.join("other/ciphervault"), b"y").unwrap();
        assert!(find_binary_in(&root, "ciphervault").is_none());
        let _ = std::fs::remove_dir_all(&root);
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
    fn asset_id_lookup_matches_by_exact_name() {
        let release: serde_json::Value = serde_json::from_str(
            r#"{"assets": [
                {"id": 11, "name": "SHA256SUMS.txt"},
                {"id": 22, "name": "ciphervault-v9-x86_64-pc-windows-msvc.zip"}
            ]}"#,
        )
        .unwrap();
        assert_eq!(
            find_asset_id(&release, "ciphervault-v9-x86_64-pc-windows-msvc.zip"),
            Some(22)
        );
        assert_eq!(find_asset_id(&release, "SHA256SUMS.txt"), Some(11));
        assert_eq!(find_asset_id(&release, "other.zip"), None);
        assert_eq!(find_asset_id(&serde_json::json!({}), "other.zip"), None);
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

    #[test]
    fn companion_names_carry_platform_suffix() {
        let operator = platform_binary_name("ciphervault-operator");
        if cfg!(windows) {
            assert_eq!(operator, "ciphervault-operator.exe");
        } else {
            assert_eq!(operator, "ciphervault-operator");
        }
        assert_eq!(COMPANION_BINARY_STEMS.len(), 3);
    }

    #[test]
    fn binary_finder_searches_nested_archive_layout() {
        let root = std::env::temp_dir().join(format!(
            "cv-update-find-{}-{}",
            std::process::id(),
            rand::random::<u32>()
        ));
        let bin_dir = root.join("ciphervault-v9-test").join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let wanted = platform_binary_name("ciphervault-operator");
        std::fs::write(bin_dir.join(&wanted), b"fake").unwrap();
        assert_eq!(find_binary_in(&root, &wanted), Some(bin_dir.join(&wanted)));
        assert_eq!(find_binary_in(&root, "no-such-binary"), None);
        std::fs::remove_dir_all(&root).unwrap();
    }

    #[test]
    fn windows_script_swaps_cli_then_companions_with_bounded_retries() {
        let script = windows_update_script(
            Path::new("C:\\bin\\ciphervault.exe.new"),
            Path::new("C:\\bin\\ciphervault.exe"),
            &[(
                PathBuf::from("C:\\bin\\op.exe.new"),
                PathBuf::from("C:\\bin\\op.exe"),
            )],
        );
        // CLI swap waits unbounded: this process is exiting.
        assert!(script.contains(":wait_cli"));
        assert!(script
            .contains("move /Y \"C:\\bin\\ciphervault.exe.new\" \"C:\\bin\\ciphervault.exe\""));
        // Companions retry ~60 s, then skip: a running daemon must not hang it.
        assert!(script.contains("set tries0=60"));
        assert!(script.contains("move /Y \"C:\\bin\\op.exe.new\" \"C:\\bin\\op.exe\""));
        assert!(script.contains("if !tries0! GTR 0"));
        assert!(script.contains("setlocal EnableDelayedExpansion"));
        assert!(script.contains("del \"%~f0\""));
    }
}
