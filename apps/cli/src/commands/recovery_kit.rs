//! Recovery-kit export, test and split commands.

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

use ciphervault_recovery::OfflineRecoveryKit;

use crate::cmd_recover;
use crate::util::{get_configured_operators, get_vault_store, RECOVERY_FILE, VAULT_DIR};

pub(crate) fn cmd_recovery_export() -> Result<()> {
    let kit_path = Path::new(VAULT_DIR).join(RECOVERY_FILE);
    if kit_path.exists() {
        let content = fs::read_to_string(kit_path)?;
        println!("{}", content);
        return Ok(());
    }

    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (sig_pk, enc_pk, locator) = store.get_recovery_descriptors()?;
    let operators = get_configured_operators();

    println!("{}", "CipherVault Public Recovery Descriptors".bold());
    println!("--------------------------------------------------------------------------------");
    println!("  Vault ID:             {}", hex::encode(vault_id).yellow());
    println!("  Recovery Signing PK:  {}", hex::encode(sig_pk).cyan());
    println!("  Recovery Encrypt PK:  {}", hex::encode(enc_pk).cyan());
    println!("  Recovery Locator:     {}", hex::encode(locator).green());
    println!("\nConfigured Recovery Operators ({}):", operators.len());
    for op in &operators {
        println!("  - {}", op.dimmed());
    }
    println!();
    println!(
        "{}",
        "In accordance with zero-disk-recovery policy, the emergency recovery secret (R)".yellow()
    );
    println!("is kept offline and is not saved unencrypted on disk.");
    println!("To test disaster recovery or restore, supply your recovery kit using:");
    println!("  ciphervault recovery test --kit <PATH> --to <TEST_DIR>");
    Ok(())
}

pub(crate) async fn cmd_recovery_test(kit_opt: Option<PathBuf>, target_dir: PathBuf) -> Result<()> {
    let kit_path = match kit_opt {
        Some(p) => p,
        None => {
            let legacy = Path::new(VAULT_DIR).join(RECOVERY_FILE);
            if legacy.exists() {
                legacy
            } else {
                bail!(
                    "No recovery kit specified and no legacy kit found at '{}'.\nSpecify the kit using: ciphervault recovery test --kit <PATH> --to {}",
                    legacy.display(),
                    target_dir.display()
                );
            }
        }
    };

    println!(
        "Running offline clean-machine recovery test into '{}'...",
        target_dir.display()
    );
    cmd_recover(Some(kit_path), None, target_dir, false).await
}

pub(crate) async fn cmd_recovery_split(
    threshold: u8,
    shares: u8,
    kit_opt: Option<PathBuf>,
    out_dir_opt: Option<PathBuf>,
) -> Result<()> {
    if threshold < 2 {
        bail!("Threshold must be at least 2 guardians");
    }
    if shares < threshold {
        bail!(
            "Total shares ({}) cannot be less than threshold ({})",
            shares,
            threshold
        );
    }

    let kit = if let Some(kit_path) = kit_opt {
        let text = fs::read_to_string(&kit_path)?;
        OfflineRecoveryKit::parse_from_printable(&text)?
    } else {
        let legacy = Path::new(VAULT_DIR).join(RECOVERY_FILE);
        if legacy.exists() {
            let text = fs::read_to_string(&legacy)?;
            OfflineRecoveryKit::parse_from_printable(&text)?
        } else {
            println!(
                "{}",
                "Splitting Master Recovery Secret into Guardian Shares".bold()
            );
            print!("Enter the 64-character hex master recovery secret (R): ");
            let _ = std::io::stdout().flush();
            let mut secret_input = String::new();
            std::io::stdin()
                .read_line(&mut secret_input)
                .context("Failed to read master recovery secret from terminal")?;
            let clean = secret_input.trim().trim_start_matches("0x");
            let mut secret_bytes = hex::decode(clean).context("Invalid hex for recovery secret")?;
            secret_input.zeroize();
            if secret_bytes.len() != 32 {
                secret_bytes.zeroize();
                bail!("Recovery secret must be exactly 32 bytes (64 hex characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&secret_bytes);
            secret_bytes.zeroize();
            let secret = ciphervault_crypto::RecoverySecret::from_bytes(arr);

            let store = get_vault_store()?;
            let vault_id = store.get_vault_id()?;
            let operators = get_configured_operators();
            OfflineRecoveryKit::create(&vault_id, &secret, operators)?
        }
    };

    println!(
        "Splitting vault {} recovery key into {}-of-{} threshold scheme...",
        kit.vault_id_hex.yellow(),
        threshold,
        shares
    );

    let guardian_kits =
        ciphervault_recovery::ThresholdRecoveryKit::split_kit(&kit, threshold, shares)?;

    if let Some(out_dir) = out_dir_opt {
        fs::create_dir_all(&out_dir)?;
        for g in &guardian_kits {
            let file_name = format!(
                "guardian_share_{}_of_{}.txt",
                g.guardian_index, g.total_shares
            );
            let file_path = out_dir.join(file_name);
            fs::write(&file_path, g.format_guardian_sheet())?;
            println!(
                "  ✓ Written guardian share {} to '{}'",
                g.guardian_index,
                file_path.display()
            );
        }
        println!(
            "\n{}",
            "Successfully exported all guardian threshold sheets!"
                .green()
                .bold()
        );
        println!(
            "Distribute each share file to a different guardian and delete the directory from this machine."
        );
    } else {
        println!(
            "\n{}",
            "================================================================================"
                .green()
        );
        for g in &guardian_kits {
            println!("{}", g.format_guardian_sheet());
        }
    }

    Ok(())
}
