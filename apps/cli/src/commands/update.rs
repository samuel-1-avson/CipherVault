//! Self-update from GitHub Releases: check the latest release, download the
//! platform archive, verify it against SHA256SUMS, and install it.
//!
//! The CLI (`ciphervault update`) and the TUI update popup share this engine;
//! only the progress reporting differs (stdout vs. status line).

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, VerifyingKey};
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
/// PowerShell extraction command for the Windows updater, with both paths
/// embedded single-quoted. powershell.exe joins everything after `-Command`
/// into ONE command line, so trailing argv entries never reach `$args` —
/// passing paths as extra argv (the pre-1.0.19 form) left `$args[0]` empty
/// and broke every Windows self-update at extraction.
fn windows_expand_archive_command(archive: &Path, dest: &Path) -> String {
    fn quote(path: &Path) -> String {
        format!("'{}'", path.to_string_lossy().replace('\'', "''"))
    }
    format!(
        "Expand-Archive -LiteralPath {} -DestinationPath {} -Force",
        quote(archive),
        quote(dest)
    )
}

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

/// Pinned release-signing trust roots: (key id, Ed25519 pubkey hex).
/// Key id = first 16 hex chars of the pubkey. Rotation appends the
/// successor here BEFORE it signs anything and removes the predecessor
/// only after every supported updater carries the successor. Trust model:
/// `docs/UPDATER_SIGNATURE_VERIFICATION.md`. The private seeds live in CI
/// secrets / offline ceremony media and never in the repo.
const RELEASE_SIGNING_KEYS: &[(&str, &str)] = &[(
    "b625994c0c3f53a6",
    "b625994c0c3f53a6c40b0eadebe7ba1f5199e9f829a4bf20e064ae7aaab22c1e",
)];

/// Detached-signature asset published next to every release archive set.
const RELEASE_SIG_ASSET: &str = "SHA256SUMS.txt.sig";

/// Only this signature envelope version is accepted; bump on format change.
const RELEASE_SIG_VERSION: &str = "CIPHERVAULT-RELEASE-SIG-V1";

/// Key id for a validated 64-char lowercase pubkey hex string.
pub(crate) fn release_key_id_of_pubkey(pubkey_hex: &str) -> String {
    pubkey_hex[..16].to_string()
}

/// True when `pubkey_hex` is a pinned release-signing key.
pub(crate) fn is_pinned_release_key(pubkey_hex: &str) -> bool {
    RELEASE_SIGNING_KEYS
        .iter()
        .any(|(_, pinned)| *pinned == pubkey_hex)
}

/// Renders the detached-signature envelope over signed `SHA256SUMS.txt` bytes.
pub(crate) fn render_release_signature(tag: &str, key_id: &str, signature_hex: &str) -> String {
    format!("{RELEASE_SIG_VERSION}\ntag: {tag}\nkey-id: {key_id}\nsignature: {signature_hex}\n")
}

/// Decodes a hex field, requiring lowercase-canonical form (same rule as
/// join invites and vouchers: one byte string, one spelling).
fn decode_canonical_hex(field: &str, what: &str, len: usize) -> Result<Vec<u8>> {
    let bytes =
        hex::decode(field).with_context(|| format!("release signature {what} must be hex"))?;
    if bytes.len() != len {
        bail!("release signature {what} must be {len} bytes");
    }
    if hex::encode(&bytes) != field {
        bail!("release signature {what} must be lowercase hex");
    }
    Ok(bytes)
}

/// Verifies a detached Ed25519 release signature over the exact
/// `SHA256SUMS.txt` bytes. The envelope binds the release tag, so a
/// signature cut from any other release is rejected even though the raw
/// Ed25519 message is the sums file alone. Returns the signing key id.
pub(crate) fn verify_release_signature(
    sums_bytes: &[u8],
    sig_text: &str,
    expected_tag: &str,
) -> Result<String> {
    let normalized = sig_text.trim_end_matches(['\r', '\n']);
    let lines: Vec<&str> = normalized.split('\n').collect();
    if lines.len() != 4 {
        bail!("release signature is malformed (expected a 4-line envelope)");
    }
    if lines[0] != RELEASE_SIG_VERSION {
        bail!(
            "release signature has unsupported version '{}' (expected {RELEASE_SIG_VERSION})",
            lines[0]
        );
    }
    let tag = lines[1]
        .strip_prefix("tag: ")
        .context("release signature is malformed (tag line)")?;
    if tag.is_empty() {
        bail!("release signature is malformed (empty tag)");
    }
    if tag != expected_tag {
        bail!("release signature is for tag '{tag}', not expected '{expected_tag}'");
    }
    let key_id = lines[2]
        .strip_prefix("key-id: ")
        .context("release signature is malformed (key-id line)")?;
    decode_canonical_hex(key_id, "key id", 8)?;
    let (_, pubkey_hex) = RELEASE_SIGNING_KEYS
        .iter()
        .find(|(id, _)| *id == key_id)
        .with_context(|| {
            format!("release signature key id '{key_id}' is not a trusted release signer")
        })?;
    let signature_hex = lines[3]
        .strip_prefix("signature: ")
        .context("release signature is malformed (signature line)")?;
    let signature_bytes = decode_canonical_hex(signature_hex, "signature", 64)?;
    let pubkey_bytes = decode_canonical_hex(pubkey_hex, "pinned key", 32)?;
    let verifying_key = VerifyingKey::from_bytes(
        pubkey_bytes
            .as_slice()
            .try_into()
            .context("pinned release key is not 32 bytes")?,
    )
    .context("pinned release key is not a valid Ed25519 key")?;
    let signature = Signature::from_bytes(
        signature_bytes
            .as_slice()
            .try_into()
            .context("release signature is not 64 bytes")?,
    );
    verifying_key
        .verify_strict(sums_bytes, &signature)
        .map_err(|_| {
            anyhow::anyhow!(
                "release signature verification failed (SHA256SUMS.txt is not signed by key '{key_id}')"
            )
        })?;
    Ok(key_id.to_string())
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
    let sig_url = asset_url(RELEASE_SIG_ASSET)
        .with_context(|| format!("release {tag} is not signed (missing {RELEASE_SIG_ASSET})"))?;
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
    on_stage("Downloading release signature...");
    let sig_text = authed_request(&client, sig_url)
        .header("Accept", "application/octet-stream")
        .send()
        .await
        .context("downloading the CipherVault release signature")?
        .error_for_status()
        .with_context(|| {
            format!("latest CipherVault release signature is unavailable ({PRIVATE_REPO_HINT})")
        })?
        .text()
        .await
        .context("reading the CipherVault release signature")?;
    on_stage("Verifying release signature...");
    let signer = verify_release_signature(sums.as_bytes(), &sig_text, tag)?;
    on_stage(&format!("Release signature valid (key {signer})."));
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
        let script = windows_expand_archive_command(&archive_path, &extract_dir);
        let status = std::process::Command::new("powershell.exe")
            .args(["-NoProfile", "-NonInteractive", "-Command", &script])
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

pub(crate) async fn cmd_update(check_only: bool, reinstall: bool) -> Result<()> {
    let check = check_for_updates().await?;
    println!(
        "Current CipherVault: {}; latest release: {}",
        check.current, check.latest_tag
    );
    // `--reinstall` forces the full verified install of the latest release
    // even when this binary already reports it (repair path; same
    // signature + checksum verification as a normal update).
    let pending = match (check.pending, reinstall) {
        (Some(pending), _) => Some(pending),
        (None, true) => {
            let (target, archive_suffix) = release_target()
                .context("No published CipherVault release for this platform".to_string())?;
            Some(PendingUpdate {
                tag: check.latest_tag.clone(),
                target,
                archive_suffix,
            })
        }
        (None, false) => None,
    };
    let Some(pending) = pending else {
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

    /// Fixture: `SHA256SUMS.txt` bytes signed offline by the pinned release
    /// key for tag `v9.9.9`. The seed never enters the repo; only the
    /// resulting signature is embedded, so this test proves the pinned
    /// trust root verifies a genuine release signature end to end.
    const FIXTURE_TAG: &str = "v9.9.9";
    const FIXTURE_SUMS: &str = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08  ciphervault-v9.9.9-x86_64-unknown-linux-gnu.tar.gz\n";
    const FIXTURE_SIG_HEX: &str = "ed0b77b87e8194636f04dcf90268a0142f1c6380bc4bbb58ba7f84592019d8e8d4699befb5ea2bd09f76badfeeea33a0fbec7522fd1e760e22bd93a47d72c303";

    fn fixture_envelope() -> String {
        render_release_signature(FIXTURE_TAG, "b625994c0c3f53a6", FIXTURE_SIG_HEX)
    }

    #[test]
    fn pinned_release_keys_are_valid_and_self_describing() {
        assert!(!RELEASE_SIGNING_KEYS.is_empty());
        for (id, pubkey) in RELEASE_SIGNING_KEYS {
            assert_eq!(release_key_id_of_pubkey(pubkey), *id);
            assert!(is_pinned_release_key(pubkey));
            let raw = hex::decode(pubkey).unwrap();
            assert_eq!(raw.len(), 32);
            let bytes: [u8; 32] = raw.try_into().unwrap();
            assert!(VerifyingKey::from_bytes(&bytes).is_ok());
        }
        assert!(!is_pinned_release_key(
            "0000000000000000000000000000000000000000000000000000000000000000"
        ));
    }

    #[test]
    fn genuine_release_signature_verifies() {
        let key_id =
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &fixture_envelope(), FIXTURE_TAG)
                .unwrap();
        assert_eq!(key_id, "b625994c0c3f53a6");
    }

    #[test]
    fn tampered_sums_rejected() {
        let tampered = FIXTURE_SUMS.replacen("9f86", "9f87", 1);
        let err = verify_release_signature(tampered.as_bytes(), &fixture_envelope(), FIXTURE_TAG)
            .unwrap_err();
        assert!(err.to_string().contains("verification failed"), "{err:#}");
    }

    #[test]
    fn flipped_signature_bit_rejected() {
        let mut bad_sig = FIXTURE_SIG_HEX.to_string();
        bad_sig.replace_range(0..1, if bad_sig.starts_with('e') { "f" } else { "e" });
        let envelope = render_release_signature(FIXTURE_TAG, "b625994c0c3f53a6", &bad_sig);
        let err =
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &envelope, FIXTURE_TAG).unwrap_err();
        assert!(err.to_string().contains("verification failed"), "{err:#}");
    }

    #[test]
    fn wrong_signer_rejected() {
        // Attacker signs the same sums with their own key but claims the
        // pinned key id: the Ed25519 check against the pinned key fails.
        use ed25519_dalek::{Signer as DalekSigner, SigningKey as DalekSigningKey};
        let attacker = DalekSigningKey::from_bytes(&[0x42; 32]);
        let forged = hex::encode(attacker.sign(FIXTURE_SUMS.as_bytes()).to_bytes());
        assert_ne!(forged, FIXTURE_SIG_HEX);
        let envelope = render_release_signature(FIXTURE_TAG, "b625994c0c3f53a6", &forged);
        let err =
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &envelope, FIXTURE_TAG).unwrap_err();
        assert!(err.to_string().contains("verification failed"), "{err:#}");
    }

    #[test]
    fn unknown_key_id_rejected() {
        // Attacker's self-consistent envelope (own key id + own signature)
        // is rejected at the trust root, before any crypto runs.
        use ed25519_dalek::{Signer as DalekSigner, SigningKey as DalekSigningKey};
        let attacker = DalekSigningKey::from_bytes(&[0x42; 32]);
        let attacker_pub = hex::encode(attacker.verifying_key().to_bytes());
        let attacker_id = release_key_id_of_pubkey(&attacker_pub);
        assert!(!is_pinned_release_key(&attacker_pub));
        let forged = hex::encode(attacker.sign(FIXTURE_SUMS.as_bytes()).to_bytes());
        let envelope = render_release_signature(FIXTURE_TAG, &attacker_id, &forged);
        let err =
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &envelope, FIXTURE_TAG).unwrap_err();
        assert!(
            err.to_string().contains("not a trusted release signer"),
            "{err:#}"
        );
    }

    #[test]
    fn cross_tag_signature_rejected() {
        // A genuine signature cut from another release does not verify for
        // this tag, even though the raw sums bytes are identical.
        let err = verify_release_signature(FIXTURE_SUMS.as_bytes(), &fixture_envelope(), "v9.9.10")
            .unwrap_err();
        assert!(err.to_string().contains("not expected"), "{err:#}");
    }

    #[test]
    fn malformed_envelopes_rejected() {
        let bad_version = fixture_envelope().replacen(
            "CIPHERVAULT-RELEASE-SIG-V1",
            "CIPHERVAULT-RELEASE-SIG-V9",
            1,
        );
        assert!(
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &bad_version, FIXTURE_TAG)
                .unwrap_err()
                .to_string()
                .contains("unsupported version")
        );
        // Truncated envelope.
        assert!(
            verify_release_signature(FIXTURE_SUMS.as_bytes(), "tag: v9.9.9\n", FIXTURE_TAG)
                .is_err()
        );
        // Empty document / unsigned artifact.
        assert!(verify_release_signature(FIXTURE_SUMS.as_bytes(), "", FIXTURE_TAG).is_err());
        // Extra trailing line.
        let extra = fixture_envelope() + "note: hello\n";
        assert!(verify_release_signature(FIXTURE_SUMS.as_bytes(), &extra, FIXTURE_TAG).is_err());
        // Uppercase hex is not canonical.
        let upper =
            fixture_envelope().replacen(FIXTURE_SIG_HEX, &FIXTURE_SIG_HEX.to_uppercase(), 1);
        assert!(
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &upper, FIXTURE_TAG)
                .unwrap_err()
                .to_string()
                .contains("lowercase hex")
        );
        // Short signature.
        let short = render_release_signature(FIXTURE_TAG, "b625994c0c3f53a6", "ab");
        assert!(verify_release_signature(FIXTURE_SUMS.as_bytes(), &short, FIXTURE_TAG).is_err());
        // Missing tag prefix.
        let no_prefix = fixture_envelope().replacen("tag: ", "", 1);
        assert!(
            verify_release_signature(FIXTURE_SUMS.as_bytes(), &no_prefix, FIXTURE_TAG).is_err()
        );
    }

    #[test]
    fn signature_then_checksum_order_pins_artifact_identity() {
        // The verified sums must still name the exact archive under install:
        // signature authenticity first, then checksum integrity of the bytes.
        assert_eq!(
            find_checksum(
                FIXTURE_SUMS,
                "ciphervault-v9.9.9-x86_64-unknown-linux-gnu.tar.gz"
            )
            .as_deref(),
            Some("9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08")
        );
        assert_eq!(
            find_checksum(
                FIXTURE_SUMS,
                "ciphervault-v9.9.10-x86_64-unknown-linux-gnu.tar.gz"
            ),
            None
        );
    }

    #[test]
    fn windows_extract_embeds_quoted_paths_without_args() {
        // Regression: powershell.exe joins everything after `-Command`
        // into one command line, so `$args[N]` placeholders never receive
        // the trailing argv. Every Windows self-update died in extraction.
        let script = windows_expand_archive_command(
            Path::new(r"C:\Temp\cv update\rel.zip"),
            Path::new(r"C:\Temp\cv update\extract"),
        );
        assert!(!script.contains("$args"), "{script}");
        assert!(
            script.contains("'C:\\Temp\\cv update\\rel.zip'"),
            "{script}"
        );
        assert!(
            script.contains("'C:\\Temp\\cv update\\extract'"),
            "{script}"
        );
        assert!(
            script.starts_with("Expand-Archive -LiteralPath "),
            "{script}"
        );
    }

    #[test]
    fn windows_extract_escapes_single_quotes() {
        let script = windows_expand_archive_command(
            Path::new(r"C:\o'brien\rel.zip"),
            Path::new(r"C:\o'brien\extract"),
        );
        assert!(script.contains("'C:\\o''brien\\rel.zip'"), "{script}");
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
