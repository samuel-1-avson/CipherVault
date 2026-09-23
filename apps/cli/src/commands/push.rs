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
        .replicate_and_verify_with_endpoints(
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
        Ok(issued) => {
            record_replication_receipts(&store, &issued);
            if issued.len() >= required_replicas {
                println!(
                    "  Durability:     {} ({}/{} independent replicas verified and read back)",
                    "RemoteDurable".green().bold(),
                    issued.len(),
                    operators.len()
                );
            } else {
                println!(
                    "  Durability:     {} ({}/{} replicas verified; degraded)",
                    "Degraded".yellow().bold(),
                    issued.len(),
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

/// Files replication receipts (push, repair) into the local lease receipt
/// log so `status --overview` shows them without a `lease list` round-trip.
/// A log failure warns instead of failing the command: the data is safe on
/// the operators and `lease list` backfills the log. Returns the count filed.
pub(crate) fn record_replication_receipts(
    store: &ciphervault_local_store::LocalVaultStore,
    issued: &[(String, ciphervault_storage::LeaseReceipt)],
) -> usize {
    let mut recorded = 0;
    for (endpoint, receipt) in issued {
        if let Err(e) = store.record_lease_receipt(
            &receipt.lease_id,
            endpoint,
            &receipt.closure_digest_hex,
            receipt.term_days,
            receipt.bytes,
            receipt.issued_at_utc,
            receipt.expires_at_utc,
            &receipt.signature_hex,
        ) {
            eprintln!(
                "warning: lease receipt log failed for {}: {e}; run `lease list` to backfill",
                receipt.lease_id
            );
            continue;
        }
        recorded += 1;
    }
    recorded
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Push-time receipt filing maps every field to the right column:
    /// distinct values per field catch transposition, and re-filing the
    /// same receipts is idempotent (INSERT OR REPLACE).
    #[test]
    fn replication_receipts_file_with_exact_fields() {
        let store = ciphervault_local_store::LocalVaultStore::open(":memory:").unwrap();
        let receipt = ciphervault_storage::LeaseReceipt {
            lease_id: "push-lease-1".to_string(),
            operator_id: "op-1".to_string(),
            closure_digest_hex: "cc".to_string(),
            term_days: 90,
            bytes: 30,
            issued_at_utc: 1000,
            expires_at_utc: 2000,
            signature_hex: "sig".to_string(),
        };
        let issued = vec![("https://op1.test".to_string(), receipt)];
        assert_eq!(record_replication_receipts(&store, &issued), 1);
        assert_eq!(record_replication_receipts(&store, &issued), 1);
        let rows = store.list_lease_receipts().unwrap();
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.lease_id, "push-lease-1");
        assert_eq!(row.operator_endpoint, "https://op1.test");
        assert_eq!(row.closure_digest_hex, "cc");
        assert_eq!(row.term_days, 90);
        assert_eq!(row.bytes, 30);
        assert_eq!(row.issued_at_utc, 1000);
        assert_eq!(row.expires_at_utc, 2000);
        assert_eq!(row.signature_hex, "sig");
    }
}
