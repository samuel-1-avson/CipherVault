//! Fleet audit and repair commands.

use anyhow::{Context, Result};
use colored::Colorize;

use ciphervault_format::to_canonical_cbor;

use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_store, resolve_required_replicas,
};

pub(crate) async fn audit_current(
    custom_operators: Option<Vec<String>>,
) -> Result<ciphervault_maintenance::engine::RecoveryAudit> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let head = store.get_active_head()?.context("No snapshot to audit")?;
    let cid: [u8; 32] = head
        .snapshot_id
        .as_slice()
        .try_into()
        .context("Invalid head CID")?;
    let set = store
        .get_recovery_set(&cid)
        .context("No recovery inventory; create a new snapshot")?;
    anyhow::ensure!(
        set.closure.compute_base_closure_digest()?.as_slice() == head.closure_digest,
        "Recovery inventory does not match signed head"
    );
    let engine = ciphervault_maintenance::MaintenanceEngine::new(
        custom_operators.unwrap_or_else(get_configured_operators),
    );
    let sessions = engine.authenticate_all(&vault_id, &device_sk).await;
    let local_objects = store.recovery_objects(&set).ok().map(|objs| {
        objs.into_iter()
            .collect::<std::collections::HashMap<[u8; 32], Vec<u8>>>()
    });
    engine
        .audit_recovery_set_with_cache(
            &set,
            &to_canonical_cbor(&head)?,
            &sessions,
            local_objects.as_ref(),
        )
        .await
}

pub(crate) async fn cmd_audit(custom_operators: Option<Vec<String>>) -> Result<()> {
    let report = audit_current(custom_operators).await?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    anyhow::ensure!(report.healthy, "Recovery set is not durable: {} complete replicas, {} lost objects, {} missing discovery logs",
        report.recoverable_operators.len(), report.objects.lost_count, report.discovery_missing.len());
    Ok(())
}

pub(crate) async fn cmd_repair(
    custom_operators: Option<Vec<String>>,
    replicas: Option<usize>,
) -> Result<()> {
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (_, device_sk, _, _) = store.get_device_state()?;
    let active_head = store
        .get_active_head()?
        .context("No active head snapshot found to repair")?;

    let operators = custom_operators.unwrap_or_else(get_configured_operators);
    println!(
        "{}",
        "Auditing and repairing degraded replicas across operators...".bold()
    );

    let engine = ciphervault_maintenance::MaintenanceEngine::new(operators.clone());
    let sessions = engine.authenticate_all(&vault_id, &device_sk).await;

    let mut head_snap_id = [0u8; 32];
    head_snap_id.copy_from_slice(&active_head.snapshot_id);

    let recovery_set = store.get_recovery_set(&head_snap_id).context("Snapshot has no complete recovery inventory; create a new snapshot before auditing or repairing")?;
    let closure = recovery_set.closure.clone();
    let objects = store.recovery_objects(&recovery_set)?;
    let local_map: std::collections::HashMap<[u8; 32], Vec<u8>> = objects.iter().cloned().collect();
    let audit = engine
        .audit_closure_with_cache(&closure, &sessions, Some(&local_map))
        .await?;
    let head_bytes = to_canonical_cbor(&active_head)?;
    let required_replicas = resolve_required_replicas(replicas)?;
    // Local verified ciphertext can also repair a total remote loss.
    configured_operator_pool(operators)
        .replicate_and_verify(
            &vault_id,
            &device_sk,
            &objects,
            &closure.compute_base_closure_digest()?,
            closure.total_bytes,
            90,
            &recovery_set.locator,
            &head_bytes,
            &recovery_set.records,
            required_replicas,
        )
        .await?;
    println!("Repair completed: complete recovery set read back on {required_replicas} operators ({} previously degraded objects).", audit.degraded_objects.len());

    Ok(())
}
