//! Passphrase-wrapped vault-key backup and restore.
//!
//! `recovery key-backup` seals the offline recovery kit with a
//! passphrase-derived key and stores the envelope as an ordinary
//! content-addressed operator object. `recovery key-restore` fetches it
//! back and unwraps it into a standard kit file. See
//! `docs/PASSPHRASE_KEY_BACKUP.md`. There is deliberately no server-side
//! unwrap: the operators only ever see the sealed envelope.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::path::PathBuf;
use zeroize::{Zeroize, Zeroizing};

use ciphervault_crypto::passphrase_backup::{open_passphrase_backup, seal_passphrase_backup};
use ciphervault_recovery::{OfflineRecoveryKit, ThresholdRecoveryKit};
use ciphervault_storage::MultiOperatorPool;

use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_store, resolve_required_replicas,
};

pub(crate) const MIN_PASSPHRASE_CHARS: usize = 12;

pub(crate) fn parse_locator(hex_str: &str) -> Result<[u8; 32]> {
    let trimmed = hex_str.trim();
    let bytes = hex::decode(trimmed).context("locator must be 64 hex characters")?;
    if bytes.len() != 32 {
        bail!("locator must be 64 hex characters");
    }
    let mut locator = [0u8; 32];
    locator.copy_from_slice(&bytes);
    Ok(locator)
}

fn check_passphrase_pair(first: &str, second: &str) -> Result<()> {
    if first != second {
        bail!("passphrases do not match");
    }
    if first.chars().count() < MIN_PASSPHRASE_CHARS {
        bail!("passphrase must be at least {MIN_PASSPHRASE_CHARS} characters");
    }
    Ok(())
}

/// Debug-only drill hatch: lets automated disaster drills supply the
/// passphrase without a TTY. Compiled out of release builds entirely, so
/// shipped binaries always use hidden console input.
#[cfg(debug_assertions)]
fn test_passphrase_source() -> Option<Zeroizing<String>> {
    let pass = std::env::var("CIPHERVAULT_TEST_PASSPHRASE").ok()?;
    if pass.is_empty() {
        return None;
    }
    eprintln!("WARNING: using TEST-ONLY debug passphrase source (never for real backups)");
    Some(Zeroizing::new(pass))
}

fn prompt_new_passphrase() -> Result<Zeroizing<String>> {
    #[cfg(debug_assertions)]
    if let Some(pass) = test_passphrase_source() {
        check_passphrase_pair(&pass, &pass)?;
        return Ok(pass);
    }
    println!(
        "{}",
        "The passphrase is the only thing protecting this backup: 6+ random words recommended, minimum 12 characters. A weak passphrase is the weak link — the operators cannot help you if it is guessed."
            .yellow()
    );
    let mut first =
        rpassword::prompt_password("Backup passphrase: ").context("passphrase input")?;
    let mut second =
        rpassword::prompt_password("Confirm passphrase: ").context("passphrase input")?;
    if let Err(error) = check_passphrase_pair(&first, &second) {
        first.zeroize();
        second.zeroize();
        return Err(error);
    }
    second.zeroize();
    Ok(Zeroizing::new(first))
}

/// Loads key material from a kit file or threshold guardian sheets and
/// returns the canonical validated kit text. Fails closed before anything
/// is sealed or written.
fn load_canonical_kit_text(
    kit: Option<PathBuf>,
    shares: Vec<PathBuf>,
) -> Result<Zeroizing<String>> {
    if !shares.is_empty() {
        let mut parsed = Vec::with_capacity(shares.len());
        for path in &shares {
            let text = Zeroizing::new(
                fs::read_to_string(path)
                    .with_context(|| format!("reading share '{}'", path.display()))?,
            );
            parsed.push(
                ThresholdRecoveryKit::parse_from_printable(&text)
                    .with_context(|| format!("parsing share '{}'", path.display()))?,
            );
        }
        let kit = ThresholdRecoveryKit::combine_kits(&parsed)?;
        let _secret = kit.validate_and_extract_secret()?;
        return Ok(Zeroizing::new(kit.format_printable()));
    }
    let Some(path) = kit else {
        bail!("provide --kit PATH or one or more --share PATH");
    };
    let text = Zeroizing::new(
        fs::read_to_string(&path).with_context(|| format!("reading kit '{}'", path.display()))?,
    );
    let kit = OfflineRecoveryKit::parse_from_printable(&text)
        .with_context(|| format!("parsing kit '{}'", path.display()))?;
    let _secret = kit.validate_and_extract_secret()?;
    Ok(Zeroizing::new(kit.format_printable()))
}

pub(crate) async fn cmd_recovery_key_backup(
    kit: Option<PathBuf>,
    shares: Vec<PathBuf>,
    replicas: Option<usize>,
) -> Result<()> {
    let canonical = load_canonical_kit_text(kit, shares)?;
    let passphrase = prompt_new_passphrase()?;
    let envelope = seal_passphrase_backup(passphrase.as_bytes(), canonical.as_bytes())?;
    drop(passphrase);
    drop(canonical);
    let cid = ciphervault_format::compute_digest(&envelope);
    let locator_hex = hex::encode(cid);

    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let operators = get_configured_operators();
    if operators.is_empty() {
        bail!("no configured operators to back up to");
    }
    let required = resolve_required_replicas(replicas)?;
    println!(
        "\nUploading {}-byte sealed backup to {} operators (need {})...",
        envelope.len(),
        operators.len(),
        required
    );
    let pool = configured_operator_pool(operators.clone());
    let authed = pool.authenticate_all(&vault_id, &device_sk).await;
    if authed.is_empty() {
        bail!("could not authenticate to any operator; nothing was stored");
    }
    let mut confirmed = 0usize;
    for (client, token) in &authed {
        match client.put_object(token, &cid, envelope.clone()).await {
            Ok(()) => match client.get_object(token, &cid).await {
                Ok(bytes) if bytes == envelope => {
                    confirmed += 1;
                    println!("  {} {}", "confirmed".green(), client.endpoint().dimmed());
                }
                Ok(_) => println!(
                    "  {} {} (readback mismatch)",
                    "skipped".yellow(),
                    client.endpoint().dimmed()
                ),
                Err(error) => println!(
                    "  {} {} ({error})",
                    "unverified".yellow(),
                    client.endpoint().dimmed()
                ),
            },
            Err(error) => println!(
                "  {} {} ({error})",
                "failed".red(),
                client.endpoint().dimmed()
            ),
        }
    }
    if confirmed < required {
        bail!("only {confirmed}/{required} replicas confirmed; backup NOT recorded — resolve operator access and retry");
    }
    let _ = store.record_activity(
        "KEYBACKUP_OK",
        &format!("Passphrase-sealed key backup confirmed on {confirmed} operators"),
        &serde_json::json!({ "locator": locator_hex, "replicas": confirmed }).to_string(),
    );
    println!("\n{}", "Backup complete.".green().bold());
    println!("  Locator: {locator_hex}");
    println!(
        "{}",
        "The locator is public but useless without the passphrase: record it on your account (dashboard: Account → Linked Vaults & Key Backups) or keep it somewhere durable and copy-pasteable. Restore with: ciphervault recovery key-restore --locator <HEX> --operator <URL> --output kit.txt".cyan()
    );
    Ok(())
}

pub(crate) async fn cmd_recovery_key_restore(
    locator: String,
    operators: Vec<String>,
    output: PathBuf,
) -> Result<()> {
    let cid = parse_locator(&locator)?;
    if operators.is_empty() {
        bail!("provide at least one --operator endpoint to fetch from");
    }
    if output.exists() {
        bail!("refusing to overwrite existing '{}'", output.display());
    }
    let pool = MultiOperatorPool::new(operators);
    let envelope = pool.fetch_object_from_any(&cid).await?;
    #[cfg(debug_assertions)]
    let passphrase = match test_passphrase_source() {
        Some(pass) => pass,
        None => Zeroizing::new(
            rpassword::prompt_password("Backup passphrase: ").context("passphrase input")?,
        ),
    };
    #[cfg(not(debug_assertions))]
    let passphrase = Zeroizing::new(
        rpassword::prompt_password("Backup passphrase: ").context("passphrase input")?,
    );
    let plaintext = open_passphrase_backup(passphrase.as_bytes(), &envelope).map_err(|_| {
        anyhow::anyhow!("could not open backup: wrong passphrase or corrupted download")
    })?;
    drop(passphrase);
    let text = Zeroizing::new(
        String::from_utf8(plaintext)
            .map_err(|_| anyhow::anyhow!("backup payload is not valid kit text"))?,
    );
    let kit = OfflineRecoveryKit::parse_from_printable(&text)?;
    let _secret = kit.validate_and_extract_secret()?;
    fs::write(&output, kit.format_printable())?;
    restrict_permissions(&output)?;
    println!("{}", "Kit restored.".green().bold());
    println!("  Wrote '{}'", output.display());
    println!(
        "{}",
        "Next: ciphervault recovery test --kit <this file> --to <TEST_DIR>. Delete this file from this machine after recovery — it holds the live recovery secret.".cyan()
    );
    Ok(())
}

#[cfg(unix)]
fn restrict_permissions(path: &std::path::Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &std::path::Path) -> std::io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locator_parsing_is_strict() {
        assert!(parse_locator(&"ab".repeat(32)).is_ok());
        assert!(parse_locator(&"  ab".repeat(32)).is_err());
        assert!(parse_locator("ab12").is_err());
        assert!(parse_locator(&"zz".repeat(32)).is_err());
        assert!(parse_locator("").is_err());
    }

    #[test]
    fn passphrase_pair_checks_match_and_length() {
        assert!(check_passphrase_pair("twelve chars!!", "twelve chars!!").is_ok());
        assert!(check_passphrase_pair("short", "short").is_err());
        assert!(check_passphrase_pair("twelve chars!!", "twelve chars!?").is_err());
    }

    #[test]
    fn kit_file_roundtrip_through_canonical_loader() {
        use ciphervault_crypto::RecoverySecret;
        let secret = RecoverySecret::from_bytes([0x42u8; 32]);
        let kit =
            OfflineRecoveryKit::create(&[0x11u8; 32], &secret, vec!["https://op.invalid".into()])
                .unwrap();
        let path = std::env::temp_dir().join(format!("cv-kit-test-{}", std::process::id()));
        fs::write(&path, kit.format_printable()).unwrap();
        let canonical = load_canonical_kit_text(Some(path.clone()), Vec::new()).unwrap();
        let reparsed = OfflineRecoveryKit::parse_from_printable(&canonical).unwrap();
        assert_eq!(reparsed.recovery_secret_hex, kit.recovery_secret_hex);
        assert_eq!(reparsed.vault_id_hex, kit.vault_id_hex);
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn loader_rejects_garbage_and_missing_input() {
        let path = std::env::temp_dir().join(format!("cv-kit-bad-{}", std::process::id()));
        fs::write(&path, "not a kit").unwrap();
        assert!(load_canonical_kit_text(Some(path.clone()), Vec::new()).is_err());
        fs::remove_file(&path).unwrap();
        assert!(load_canonical_kit_text(None, Vec::new()).is_err());
    }
}
