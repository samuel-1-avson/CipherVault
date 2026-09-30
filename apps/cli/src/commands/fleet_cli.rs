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
    let pool = configured_operator_pool(custom_operators.unwrap_or_else(get_configured_operators));
    let engine = ciphervault_maintenance::MaintenanceEngine::from_clients(pool.clients().to_vec());
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

pub(super) async fn export_maintenance_inventory(
    path: &std::path::Path,
    endpoints: Option<Vec<String>>,
    supplied_pins: Vec<String>,
) -> Result<ciphervault_maintenance::scheduler::MaintenanceInventory> {
    use ciphervault_local_store::AccountStore;
    use std::io::Write;
    let store = get_vault_store()?;
    let vault_id = store.get_vault_id()?;
    let (device_id, device_key, _, _) = store.get_device_state()?;
    let head = store
        .get_active_head()?
        .context("Capture a snapshot before exporting inventory")?;
    let cid: [u8; 32] = head.snapshot_id.as_slice().try_into()?;
    let set = store.get_recovery_set(&cid)?;
    let (recovery_signing_pk, _, _) = store.get_recovery_descriptors()?;
    let mut pins = crate::util::configured_operator_pins()?;
    for entry in &supplied_pins {
        let (endpoint, key) = entry
            .rsplit_once('=')
            .context("--operator-pin must be endpoint=64hex")?;
        let decoded = hex::decode(key.trim()).context("Invalid signing-key hex")?;
        pins.insert(
            endpoint.trim().trim_end_matches('/').to_string(),
            decoded
                .as_slice()
                .try_into()
                .context("Operator signing key must be 32 bytes")?,
        );
    }
    let endpoints = endpoints.unwrap_or_else(get_configured_operators);
    let mut operator_keys = std::collections::HashMap::new();
    let account_binding = AccountStore::open(None).ok().filter(|account| {
        account.is_vault_linked(&hex::encode(vault_id))
            && account.is_device_active(
                &hex::encode(device_id),
                &hex::encode(device_key.verifying_key().to_bytes()),
            )
    });
    let mut leases = Vec::new();
    for endpoint in endpoints {
        let endpoint = endpoint.trim_end_matches('/').to_string();
        let key = *pins.get(&endpoint).with_context(|| format!("No independently trusted signing key for {endpoint}; provide --operator-pin or operator_pins.json"))?;
        let client = ciphervault_storage::OperatorClient::new_pinned(endpoint.clone(), key);
        if let Some(account) = &account_binding {
            client.with_account_identity(account.account_id(), hex::encode(device_id));
        }
        client
            .get_info_pinned(&key)
            .await
            .context("Verifying independently enrolled operator identity")?;
        if let Ok(session) = client.authenticate(&vault_id, &device_key).await {
            if let Ok(response) = client.list_leases(&session, 500).await {
                for receipt in response.leases {
                    if receipt.closure_digest_hex
                        == hex::encode(set.closure.compute_base_closure_digest()?)
                        && receipt.verify(&key).is_ok()
                    {
                        leases.push(receipt);
                    }
                }
            }
        }
        operator_keys.insert(endpoint, key);
    }
    let inventory = ciphervault_maintenance::scheduler::MaintenanceInventory {
        set,
        head: to_canonical_cbor(&head)?,
        vault_id,
        recovery_signing_pk,
        operator_keys,
        required_replicas: ciphervault_storage::pool::DEFAULT_REQUIRED_REPLICAS,
        leases,
        account_id: account_binding
            .as_ref()
            .map(|account| account.account_id().to_string()),
        device_id_hex: account_binding.as_ref().map(|_| hex::encode(device_id)),
    };
    inventory.validate()?;
    let mut output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .context("Inventory output must be a new file")?;
    output.write_all(serde_json::to_string_pretty(&inventory)?.as_bytes())?;
    output.sync_all()?;
    println!(
        "Exported authenticated public maintenance inventory to {}",
        path.display()
    );
    Ok(inventory)
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

    let pool = configured_operator_pool(operators.clone());
    let engine = ciphervault_maintenance::MaintenanceEngine::from_clients(pool.clients().to_vec());
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
    let issued = configured_operator_pool(operators)
        .replicate_and_verify_with_endpoints(
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
    super::push::record_replication_receipts(&store, &issued);
    println!("Repair completed: complete recovery set read back on {required_replicas} operators ({} previously degraded objects).", audit.degraded_objects.len());

    Ok(())
}
