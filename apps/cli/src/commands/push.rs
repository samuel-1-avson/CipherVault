//! Snapshot push command.

use anyhow::{bail, Result};
use colored::Colorize;

use ciphervault_format::{to_canonical_cbor, HeadRecord, PROTOCOL_VERSION};
use ciphervault_snapshot::{create_snapshot, create_snapshot_with_signer, DeviceSigner};

use crate::cmd_anchor;
use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_store, resolve_hardware_token,
    resolve_required_replicas,
};

#[allow(
    clippy::too_many_arguments,
    reason = "One arg per push flag; matches the existing CLI plumbing style"
)]
pub(crate) async fn cmd_push(
    message: Option<String>,
    touch: bool,
    local: bool,
    anchor: bool,
    reader: Option<String>,
    pin: Option<String>,
    concurrency: Option<usize>,
    replicas: Option<usize>,
) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_sk, counter, epoch) = store.get_device_state()?;
    let epoch_key = store.get_epoch_key(epoch)?;
    let tracked = store.list_tracked_files()?;

    if tracked.is_empty() {
        bail!(
            "No files are tracked. Track files using '{}' before pushing.",
            "ciphervault track <path>".cyan()
        );
    }

    let active_head = store.get_active_head()?;
    let parent_ids = match active_head {
        Some(ref h) => vec![{
            let mut arr = [0u8; 32];
            arr.copy_from_slice(&h.snapshot_id);
            arr
        }],
        None => Vec::new(),
    };

    let certs = store.list_device_certificates()?;
    let is_hardware_bound = certs
        .first()
        .map(|c| c.device_signing_pk != device_sk.verifying_key().to_bytes())
        .unwrap_or(false);

    let maybe_token = if touch || is_hardware_bound {
        if touch {
            println!(
                "{}",
                "Hardware Touch Presence Authorization (--touch):"
                    .bold()
                    .yellow()
            );
            println!(
                "  Please tap your physical YubiKey / hardware token to sign snapshot commit..."
            );
        } else {
            println!("{}", "Hardware-Bound Vault Signing Ceremony:".bold().cyan());
            println!(
                "  Using physical YubiKey / hardware token (Slot 9C) for snapshot signature..."
            );
        }
        let token = resolve_hardware_token(reader.as_deref(), pin.as_deref(), false)?;
        println!("  Found token on reader: {}", token.reader_name().cyan());
        Some(token)
    } else {
        None
    };

    println!("{}", "Capturing and encrypting snapshot...".bold());

    let current_dir = std::env::current_dir()?;
    let output = match &maybe_token {
        Some(token) => create_snapshot_with_signer(
            &current_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids.clone(),
            &device_id,
            counter + 1,
            1, // authority generation
            &DeviceSigner::Hardware(token, ciphervault_crypto::HsmSlot::DigitalSignature),
        )?,
        None => create_snapshot(
            &current_dir,
            &tracked,
            &vault_id,
            epoch,
            &epoch_key,
            parent_ids.clone(),
            &device_id,
            counter + 1,
            1, // authority generation
            &device_sk,
        )?,
    };

    // Store snapshot and chunks in local transactional queue
    store.save_snapshot(&output.record, &output.encrypted_manifest, &output.chunks)?;
    store.increment_device_counter()?;

    let recovery_set = store.prepare_recovery_set(&output.record)?;
    let record_cid = output.record.compute_record_cid()?;

    // Create and sign updated HeadRecord pointing to snapshot-record CID
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: record_cid.to_vec(),
        parent_snapshot_ids: output.record.parent_snapshot_ids.clone(),
        closure_digest: recovery_set.closure.compute_base_closure_digest()?.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: counter + 1,
        signature: Vec::new(),
    };

    if let Some(ref token) = maybe_token {
        head.sign_with_hsm(token, ciphervault_crypto::HsmSlot::DigitalSignature)?;
        if touch {
            println!(
                "  {}",
                "✓ Physical touch presence confirmed!".green().bold()
            );
        } else {
            println!(
                "  {}",
                "✓ Hardware token Slot 9C signature confirmed!"
                    .green()
                    .bold()
            );
        }
    } else {
        head.sign(&device_sk)?;
    }

    store.set_head(&head)?;

    let snapshot_hex = hex::encode(&output.record.snapshot_id);
    println!(
        "{}",
        "✓ Snapshot captured and encrypted locally!".bold().green()
    );
    println!("  Snapshot ID:    {}", snapshot_hex.yellow());
    println!("  Files captured: {}", tracked.len());
    println!("  Plaintext size: {} bytes", output.closure.total_bytes);
    println!("  Chunks created: {}", output.chunks.len());
    if let Some(msg) = message {
        println!("  Message:        \"{}\"", msg);
    }

    if local {
        println!(
            "  Durability:     {} (offline / local-only commit)",
            "LocalOnly".yellow().bold()
        );
        return Ok(());
    }

    // Attempt multi-operator replication
    let operators = get_configured_operators();
    println!(
        "\nReplicating across {} independent operators...",
        operators.len()
    );

    let pool = configured_operator_pool(operators.clone());
    let trace_id = ciphervault_storage::client::OperatorClient::new_trace_id();
    pool.set_trace_id(&trace_id);
    if let Some(requested) = concurrency {
        if !(1..=ciphervault_storage::pool::MAX_OBJECT_CONCURRENCY).contains(&requested) {
            eprintln!(
                "warning: --concurrency {requested} out of range, clamped to 1-{}",
                ciphervault_storage::pool::MAX_OBJECT_CONCURRENCY
            );
        }
        pool.set_object_concurrency(requested);
    }

    let wire_objects = store.recovery_objects(&recovery_set)?;
    let head_cbor = to_canonical_cbor(&head)?;
    let closure_digest = recovery_set.closure.compute_base_closure_digest()?;
    let required_replicas = resolve_required_replicas(replicas)?;
    let replication_started = std::time::Instant::now();
    let rep_result = pool
        .replicate_and_verify(
            &vault_id,
            &device_sk,
            &wire_objects,
            &closure_digest,
            output.closure.total_bytes,
            90, // 90-day retention
            &recovery_set.locator,
            &head_cbor,
            &recovery_set.records,
            required_replicas,
        )
        .await;

    match rep_result {
        Ok(receipts) => {
            if receipts.len() >= required_replicas {
                println!(
                    "  Durability:     {} ({}/{} independent replicas verified and read back)",
                    "RemoteDurable".green().bold(),
                    receipts.len(),
                    operators.len()
                );
            } else {
                println!(
                    "  Durability:     {} ({}/{} replicas verified; degraded)",
                    "Degraded".yellow().bold(),
                    receipts.len(),
                    operators.len()
                );
            }
            println!(
                "  Replication:    {:.2}s (trace {})",
                replication_started.elapsed().as_secs_f64(),
                trace_id
            );
        }
        Err(e) => {
            println!(
                "  Durability:     {} (Remote upload failed: {})",
                "Local only".yellow().bold(),
                e
            );
            println!("  Trace ID:       {trace_id}");
            return Err(e.into());
        }
    }

    if anchor {
        println!(
            "{}",
            "Triggering automated post-push Arbitrum L2 anchoring...".cyan()
        );
        if let Err(e) = cmd_anchor(None, None, None, None, None, None, true, None).await {
            eprintln!("{}: {}", "Notice: Post-push anchoring failed".yellow(), e);
        }
    }

    Ok(())
}
