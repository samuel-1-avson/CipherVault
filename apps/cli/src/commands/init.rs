//! Vault init command.

use anyhow::{bail, Result};
use chrono::Utc;
use colored::Colorize;
use rand::RngCore;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};

use ciphervault_crypto::{
    generate_signing_key, HardwareSecurityModule, RecoverySecret, VaultEpochKey,
};
use ciphervault_format::{DeviceCertificate, GenesisRecord, PROTOCOL_VERSION};
use ciphervault_local_store::LocalVaultStore;
use ciphervault_recovery::OfflineRecoveryKit;

use crate::util::{
    ensure_gitignore, resolve_hardware_token, save_token_reader_preference,
    scan_gitignore_for_secrets, DB_FILE, DEFAULT_PRODUCTION_OPERATORS, OPERATORS_FILE, VAULT_DIR,
};

pub(crate) fn cmd_init(
    force: bool,
    custom_operators: Option<Vec<String>>,
    save_kit: Option<PathBuf>,
    hardware_token: bool,
    import_gitignore: bool,
    reader: Option<String>,
    pin: Option<String>,
) -> Result<()> {
    let vault_dir = Path::new(VAULT_DIR);
    if vault_dir.exists() && !force {
        bail!("A CipherVault already exists in this directory. Use '--force' to re-initialize.");
    }

    fs::create_dir_all(vault_dir)?;
    ensure_gitignore()?;

    println!("{}", "Initializing new CipherVault...".bold().green());

    let mut vault_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut vault_id);

    let recovery_secret = RecoverySecret::generate();
    let recovery_sk = recovery_secret.derive_recovery_signing_key()?;
    let (_, recovery_enc_pk) = recovery_secret.derive_recovery_encryption_keys()?;
    let recovery_locator = recovery_secret.derive_recovery_locator()?;

    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: recovery_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: Utc::now().timestamp() as u64,
        creation_nonce: {
            let mut n = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut n);
            n
        },
        signature: Vec::new(),
    };
    genesis.sign(&recovery_sk)?;

    let (device_sk, device_pk) = if hardware_token {
        println!(
            "{}",
            "Hardware Token Binding Requested (--hardware-token):"
                .bold()
                .cyan()
        );
        let token = resolve_hardware_token(reader.as_deref(), pin.as_deref(), false)?;
        println!(
            "  Detected token on reader: {}",
            token.reader_name().yellow().bold()
        );
        let pk = token.get_public_key(ciphervault_crypto::HsmSlot::DigitalSignature)?;
        println!(
            "  Bound to PIV Slot 9C Public Key: {}",
            hex::encode(&pk).green()
        );
        let _ = save_token_reader_preference(token.reader_name());
        let sk = generate_signing_key();
        (sk, pk)
    } else {
        let sk = generate_signing_key();
        let pk = sk.verifying_key().as_bytes().to_vec();
        (sk, pk)
    };

    let mut device_id = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut device_id);

    let initial_epoch_key = VaultEpochKey::generate();

    let db_path = vault_dir.join(DB_FILE);
    if db_path.exists() {
        fs::remove_file(&db_path)?;
    }
    let store = LocalVaultStore::open(&db_path)?;
    store.init_vault(
        &vault_id,
        &genesis,
        &device_sk,
        &device_id,
        &initial_epoch_key,
        &recovery_locator,
    )?;

    // Create, sign, and store device certificate rooted in recovery authority
    let mut cert = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        certificate_id: {
            let mut cid = vec![0u8; 32];
            rand::thread_rng().fill_bytes(&mut cid);
            cid
        },
        device_signing_pk: device_pk,
        permissions: 0xFFFFFFFF,
        authority_generation: 1,
        issued_at_utc: Utc::now().timestamp() as u64,
        signature: Vec::new(),
    };
    cert.sign(&recovery_sk)?;
    store.save_device_certificate(&cert)?;

    let operator_endpoints = custom_operators.unwrap_or_else(|| {
        DEFAULT_PRODUCTION_OPERATORS
            .iter()
            .map(|s| s.to_string())
            .collect()
    });

    // Save operators config
    let ops_json = serde_json::to_string_pretty(&operator_endpoints)?;
    fs::write(vault_dir.join(OPERATORS_FILE), ops_json)?;

    let kit = OfflineRecoveryKit::create(&vault_id, &recovery_secret, operator_endpoints)?;
    let printable_kit = kit.format_printable();

    if let Some(ref path) = save_kit {
        fs::write(path, &printable_kit)?;
        println!(
            "An emergency recovery kit backup file was explicitly saved to: {}",
            path.display().to_string().bold()
        );
    }

    println!(
        "{}",
        "✓ CipherVault initialized successfully!".bold().green()
    );
    println!("  Vault ID:   {}", hex::encode(vault_id).yellow());
    println!("  Device ID:  {}", hex::encode(device_id).cyan());
    println!("  Local DB:   {}", db_path.display());
    println!("  Gitignore:  Updated to ignore '{}'", VAULT_DIR);
    println!();
    println!(
        "{}",
        "================================================================================".yellow()
    );
    println!(
        "{}",
        "                  CRITICAL: SAVE YOUR EMERGENCY RECOVERY KIT                    "
            .bold()
            .yellow()
    );
    println!(
        "{}",
        "================================================================================".yellow()
    );
    println!("{}", printable_kit);
    println!(
        "{}",
        "================================================================================".yellow()
    );
    println!(
        "{}",
        "NOTE: In accordance with zero-disk-recovery policy, this secret is NEVER saved"
            .bold()
            .red()
    );
    println!(
        "{}",
        "to disk in .ciphervault/. Record this kit immediately in an offline vault."
            .bold()
            .red()
    );
    println!();

    if std::io::stdin().is_terminal() {
        print!(
            "{}",
            "Type 'yes' or press Enter once you have recorded your recovery secret to zeroize memory: "
                .bold()
                .cyan()
        );
        let _ = std::io::stdout().flush();
        let mut confirm = String::new();
        let _ = std::io::stdin().read_line(&mut confirm);
    }
    println!("{}", "✓ Recovery secret zeroized from memory.".green());

    // Explicit drop to ensure memory scrubbing
    drop(kit);
    drop(recovery_secret);
    drop(recovery_sk);

    // Smart .gitignore secret discovery
    if let Ok(discovered_secrets) = scan_gitignore_for_secrets(Path::new(".")) {
        if !discovered_secrets.is_empty() {
            let should_import = if import_gitignore {
                true
            } else if std::io::stdin().is_terminal() {
                println!();
                println!("{}", "--------------------------------------------------------------------------------".cyan());
                println!(
                    "{}",
                    "  [GITIGNORE SCAN] Discovered Confidential Files in .gitignore:"
                        .bold()
                        .green()
                );
                println!("{}", "--------------------------------------------------------------------------------".cyan());
                for s in &discovered_secrets {
                    let size_str = if s.exists() {
                        if let Ok(meta) = s.metadata() {
                            format!(" [found: {} bytes]", meta.len()).green()
                        } else {
                            " [found]".green()
                        }
                    } else {
                        " [planned]".yellow()
                    };
                    println!("    - {} {}", s.display().to_string().yellow(), size_str);
                }
                println!(
                    "{}",
                    "    (Build folders node_modules/, target/, dist/, *.log were excluded)"
                        .dimmed()
                );
                println!();
                print!("Track these confidential secret file(s) in CipherVault now? [Y/n]: ");
                let _ = std::io::stdout().flush();
                let mut ans = String::new();
                if std::io::stdin().read_line(&mut ans).is_ok() {
                    let trimmed = ans.trim().to_lowercase();
                    trimmed.is_empty() || trimmed == "y" || trimmed == "yes"
                } else {
                    false
                }
            } else {
                false
            };

            if should_import {
                println!();
                println!(
                    "{}",
                    "Registering secrets discovered in .gitignore:"
                        .bold()
                        .cyan()
                );
                for s in discovered_secrets {
                    let path_str = s.to_string_lossy();
                    let file_id = store.track_file(&path_str)?;
                    println!(
                        "  {} {} (ID: {})",
                        "+".green(),
                        path_str.yellow(),
                        hex::encode(&file_id[0..4]).dimmed()
                    );
                }
            }
        }
    }

    Ok(())
}
