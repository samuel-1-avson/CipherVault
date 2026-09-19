//! Snapshot run command (execute against a decrypted snapshot).

use anyhow::{bail, Context, Result};
use colored::Colorize;
use std::path::Path;
use zeroize::Zeroize;

use ciphervault_format::{from_canonical_cbor, ChunkWireObject, SnapshotManifest};
use ciphervault_snapshot::decrypt_snapshot;

use crate::dotenv;
use crate::util::{configured_operator_pool, get_configured_operators, get_vault_store};

pub(crate) async fn cmd_run(
    snapshot_hex_opt: Option<String>,
    env_file_opt: Option<String>,
    no_inherit: bool,
    dry_run: bool,
    quiet: bool,
    set_overrides: Option<Vec<String>>,
    command: Vec<String>,
) -> Result<()> {
    if command.is_empty() {
        bail!("No command specified to execute. Usage: ciphervault run [OPTIONS] -- <COMMAND> [ARGS]...");
    }

    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, _, _, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;

    let snapshot_id = match snapshot_hex_opt {
        Some(hex_str) => {
            let bytes = hex::decode(hex_str.trim())?;
            if bytes.len() != 32 {
                bail!("Snapshot ID must be 32 bytes hex string (64 characters)");
            }
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&bytes);
            arr
        }
        None => {
            let head = store
                .get_active_head()?
                .context("Vault has no snapshots committed yet. Create a snapshot first with 'ciphervault push'")?;
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&head.snapshot_id);
            arr
        }
    };

    let (record, encrypted_manifest) = store.get_snapshot(&snapshot_id)?;

    let manifest_key = epoch_key.derive_manifest_key(record.epoch)?;
    let aad = [
        b"CipherVault-Manifest:",
        vault_id.as_slice(),
        &record.epoch.to_le_bytes(),
    ]
    .concat();
    let manifest_bytes =
        ciphervault_crypto::decrypt_chunk(&manifest_key, &encrypted_manifest, &aad)?;
    let manifest: SnapshotManifest = from_canonical_cbor(&manifest_bytes)?;

    let mut needed_cids = Vec::new();
    for file in &manifest.files {
        for cid_bytes in &file.chunk_cids {
            let mut arr = [0u8; 32];
            arr.copy_from_slice(cid_bytes);
            needed_cids.push(arr);
        }
    }

    let mut chunks = store.get_chunks(&needed_cids)?;
    if chunks.len() != needed_cids.len() {
        // Attempt to fetch missing chunks from configured operators
        let existing_cids: std::collections::HashSet<[u8; 32]> =
            chunks.iter().filter_map(|c| c.compute_cid().ok()).collect();
        let missing_cids: Vec<[u8; 32]> = needed_cids
            .iter()
            .copied()
            .filter(|cid| !existing_cids.contains(cid))
            .collect();

        let operators = get_configured_operators();
        if !operators.is_empty() {
            let pool = configured_operator_pool(operators);
            for cid in &missing_cids {
                if let Ok(bytes) = pool.fetch_object_from_any(cid).await {
                    if let Ok(chunk) = from_canonical_cbor::<ChunkWireObject>(&bytes) {
                        chunks.push(chunk);
                    }
                }
            }
        }

        if chunks.len() != needed_cids.len() {
            bail!(
                "Cannot execute: missing {} encrypted chunk(s) across local store and operators",
                needed_cids.len() - chunks.len()
            );
        }
    }

    // Decrypt snapshot files strictly in volatile memory (zero disk exposure)
    let mut decrypted_files = decrypt_snapshot(
        &vault_id,
        &epoch_key,
        record.epoch,
        &encrypted_manifest,
        &chunks,
    )?;

    // Select which file(s) to load environment variables from
    let mut loaded_vars: Vec<(String, String)> = Vec::new();
    let mut loaded_from_files: Vec<String> = Vec::new();

    if let Some(target_file) = env_file_opt {
        let norm_target = target_file.replace('\\', "/");
        let matched = decrypted_files
            .iter()
            .find(|f| f.relative_path.replace('\\', "/") == norm_target);

        match matched {
            Some(file) => {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(parsed);
            }
            None => {
                bail!(
                    "Specified env file '{}' not found in snapshot {}",
                    target_file,
                    &hex::encode(snapshot_id)[..12]
                );
            }
        }
    } else {
        // Auto-detect .env files: load .env first, then other .env.* files
        let mut env_files: Vec<&ciphervault_snapshot::DecryptedFile> = decrypted_files
            .iter()
            .filter(|f| {
                let p = f.relative_path.replace('\\', "/");
                let name = p.rsplit('/').next().unwrap_or(&p);
                name == ".env" || name.starts_with(".env.") || name.ends_with(".env")
            })
            .collect();

        // Sort so that .env is base and .env.local / .env.production override earlier keys
        env_files.sort_by_key(|f| {
            let p = f.relative_path.replace('\\', "/");
            let name = p.rsplit('/').next().unwrap_or(&p);
            if name == ".env" {
                0
            } else {
                1
            }
        });

        if env_files.is_empty() {
            if !quiet {
                eprintln!(
                    "{}",
                    "⚠️  No .env files found in snapshot; running with existing environment only."
                        .yellow()
                );
            }
        } else {
            for file in env_files {
                let parsed = dotenv::parse_dotenv_bytes(&file.plaintext).map_err(|e| {
                    anyhow::anyhow!("Failed to parse '{}': {}", file.relative_path, e)
                })?;
                loaded_from_files.push(file.relative_path.clone());
                loaded_vars.extend(parsed);
            }
        }
    }

    // Apply additional --set overrides
    if let Some(overrides) = set_overrides {
        for item in overrides {
            if let Some((k, v)) = item.split_once('=') {
                loaded_vars.push((k.trim().to_string(), v.to_string()));
            } else {
                bail!("Invalid --set format: expected KEY=VALUE, got '{}'", item);
            }
        }
    }

    // Cleanly deduplicate keys, keeping the last definition
    let mut deduped_vars: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (k, v) in loaded_vars {
        deduped_vars.insert(k, v);
    }

    // Dry Run Mode
    if dry_run {
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!(
            "  {}",
            "CipherVault Zero-Disk Secret Injection (Dry Run)"
                .bold()
                .green()
        );
        println!(
            "{}",
            "=======================================================".cyan()
        );
        println!("Snapshot: {}", hex::encode(snapshot_id)[..12].yellow());
        println!("Sources:  {}", loaded_from_files.join(", ").cyan());
        println!(
            "Secrets:  {} variable(s) ready for injection",
            deduped_vars.len()
        );
        println!();
        for k in deduped_vars.keys() {
            println!("  • {} = [REDACTED]", k.bold().white());
        }
        println!();
        println!(
            "{}",
            "✓ Zero secrets written to disk. Exiting without execution.".green()
        );

        // Zeroize memory buffers
        for f in &mut decrypted_files {
            f.plaintext.zeroize();
        }
        return Ok(());
    }

    #[cfg(target_os = "windows")]
    fn resolve_windows_command(exe: &str) -> (String, Vec<String>) {
        let p = Path::new(exe);
        if p.extension().is_some() || exe.contains('\\') || exe.contains('/') {
            return (exe.to_string(), Vec::new());
        }

        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD".to_string());
        let extensions: Vec<&str> = pathext.split(';').filter(|s| !s.is_empty()).collect();

        if let Ok(path_var) = std::env::var("PATH") {
            for dir in std::env::split_paths(&path_var) {
                for ext in &extensions {
                    let candidate = dir.join(format!("{}{}", exe, ext));
                    if candidate.is_file() {
                        let ext_upper = ext.to_uppercase();
                        if ext_upper == ".CMD" || ext_upper == ".BAT" {
                            return (
                                "cmd.exe".to_string(),
                                vec!["/c".to_string(), candidate.to_string_lossy().to_string()],
                            );
                        }
                        return (candidate.to_string_lossy().to_string(), Vec::new());
                    }
                }
            }
        }

        (exe.to_string(), Vec::new())
    }

    // Configure Child Command
    let exe = &command[0];
    let raw_args = &command[1..];

    #[cfg(target_os = "windows")]
    let (target_bin, prefix_args) = resolve_windows_command(exe);
    #[cfg(not(target_os = "windows"))]
    let (target_bin, prefix_args): (String, Vec<String>) = (exe.clone(), Vec::new());

    let mut cmd = std::process::Command::new(&target_bin);
    if !prefix_args.is_empty() {
        cmd.args(&prefix_args);
    }
    cmd.args(raw_args);

    if no_inherit {
        cmd.env_clear();
        // Retain essential operating system paths so standard binaries and runtimes function
        for (k, v) in std::env::vars() {
            let k_upper = k.to_uppercase();
            if k_upper == "PATH"
                || k_upper == "SYSTEMROOT"
                || k_upper == "TEMP"
                || k_upper == "TMP"
                || k_upper == "USERPROFILE"
                || k_upper == "HOME"
                || k_upper == "COMSPEC"
                || k_upper == "PATHEXT"
            {
                cmd.env(k, v);
            }
        }
    }

    // Inject decrypted secrets
    for (k, v) in &deduped_vars {
        cmd.env(k, v);
    }

    if !quiet {
        eprintln!(
            "{} Injected {} secret(s) from snapshot {} into '{}'",
            "[ciphervault]".bold().cyan(),
            deduped_vars.len().to_string().bold().green(),
            hex::encode(snapshot_id)[..8].yellow(),
            exe.white()
        );
    }

    // Zeroize decrypted memory buffers prior to child process execution
    for f in &mut decrypted_files {
        f.plaintext.zeroize();
    }

    // Spawn child process with inherited stdio
    cmd.stdin(std::process::Stdio::inherit());
    cmd.stdout(std::process::Stdio::inherit());
    cmd.stderr(std::process::Stdio::inherit());

    let mut child = cmd
        .spawn()
        .with_context(|| format!("Failed to spawn command '{}'", exe))?;

    let status = child
        .wait()
        .with_context(|| format!("Failed to wait on child process '{}'", exe))?;

    let exit_code = status.code().unwrap_or(1);
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}
