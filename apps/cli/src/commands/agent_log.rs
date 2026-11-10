//! Tamper-evident agent-access audit log: what AI-agent tools did
//! around this vault's secrets (blocked reads, approval requests,
//! scrubbed results, writes). Hash-chained and device-signed in the
//! local store; entries carry paths/decisions/counts, never contents.

use anyhow::{bail, ensure, Result};
use ed25519_dalek::Signer;
use sha2::Digest;
use std::io::Write;

use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_directory, get_vault_store,
};
use crate::AgentLogSubcommand;

#[derive(serde::Serialize, serde::Deserialize)]
struct AuditCheckpoint {
    kind: String,
    vault_id: String,
    entries: usize,
    head_hash: String,
    created_at_utc: i64,
    signature: String,
}

fn checkpoint_payload(vault_id: &str, entries: usize, head_hash: &str, ts: i64) -> String {
    format!("agent-audit-checkpoint\n{vault_id}\n{entries}\n{head_hash}\n{ts}")
}

/// Anchors the current audit-chain head to the operator fleet as a
/// signed, content-addressed checkpoint object, so the receipt lives
/// outside the agent's control. Returns (operators_confirmed, cid,
/// entries, head_hash).
pub(crate) async fn anchor_agent_audit(
    endpoints: &[String],
) -> Result<(usize, String, usize, String)> {
    // All store access happens synchronously here, and the store is
    // dropped before the first await: the vault store is !Send, so no
    // borrow of it may be captured by this future.
    let (bytes, cid, vault_id, device_sk, entries, head_hash) = {
        let store = get_vault_store()?;
        let report = store.verify_agent_audit()?;
        ensure!(report.ok, "audit chain is broken; refusing to anchor");
        let vault_id = store.get_vault_id()?;
        let vault_hex = hex::encode(vault_id);
        let (_, device_sk, _, _) = store.get_device_state()?;
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let signature = hex::encode(
            device_sk
                .sign(
                    checkpoint_payload(&vault_hex, report.entries, &report.head_hash, ts)
                        .as_bytes(),
                )
                .to_bytes(),
        );
        let checkpoint = AuditCheckpoint {
            kind: "agent-audit-checkpoint".to_string(),
            vault_id: vault_hex,
            entries: report.entries,
            head_hash: report.head_hash.clone(),
            created_at_utc: ts,
            signature,
        };
        let bytes = serde_json::to_vec(&checkpoint)?;
        let cid: [u8; 32] = sha2::Sha256::digest(&bytes).into();
        (
            bytes,
            cid,
            vault_id,
            device_sk,
            report.entries,
            report.head_hash,
        )
    };
    let pool = configured_operator_pool(endpoints.to_vec());
    let mut confirmed = 0usize;
    for client in pool.clients() {
        if let Ok(token) = client.authenticate(&vault_id, &device_sk).await {
            if client.put_object(&token, &cid, bytes.clone()).await.is_ok() {
                confirmed += 1;
            }
        }
    }
    ensure!(confirmed > 0, "no operator confirmed the audit checkpoint");
    let record = serde_json::json!({
        "cid": hex::encode(cid),
        "entries": entries,
        "head_hash": head_hash,
        "operators_confirmed": confirmed,
    });
    std::fs::write(
        get_vault_directory().join("audit_checkpoint.json"),
        serde_json::to_string_pretty(&record)?,
    )?;
    Ok((confirmed, hex::encode(cid), entries, head_hash))
}

pub(crate) async fn cmd_agent_log(sub: AgentLogSubcommand) -> Result<()> {
    let store = get_vault_store()?;
    match sub {
        AgentLogSubcommand::Record {
            tool,
            decision,
            path,
            detail,
        } => {
            let entry = store.append_agent_audit(&tool, &decision, &path, &detail)?;
            println!("{}", serde_json::to_string(&entry)?);
        }
        AgentLogSubcommand::Show { limit, json } => {
            let entries = store.list_agent_audit(limit)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&entries)?);
            } else if entries.is_empty() {
                println!("agent audit log is empty");
            } else {
                for e in &entries {
                    println!(
                        "#{} {} {} {} {} {}",
                        e.id, e.created_at_utc, e.tool, e.decision, e.path, e.detail_json
                    );
                }
            }
        }
        AgentLogSubcommand::Verify { json } => {
            let report = store.verify_agent_audit()?;
            if json {
                println!("{}", serde_json::to_string_pretty(&report)?);
            } else if report.ok {
                println!(
                    "agent audit chain OK: {} entries, head {}",
                    report.entries,
                    &report.head_hash[..report.head_hash.len().min(16)]
                );
            } else {
                println!(
                    "agent audit chain BROKEN at entry {:?} (after {} entries)",
                    report.first_bad_id, report.entries
                );
            }
            if !report.ok {
                bail!("agent audit verification failed");
            }
        }
        AgentLogSubcommand::Check {
            output_sha256,
            json,
        } => {
            // A lookup is only proof if the chain itself verifies —
            // otherwise a forged row could "prove" anything.
            let report = store.verify_agent_audit()?;
            ensure!(
                report.ok,
                "audit chain is broken at entry {:?}; refusing to treat a lookup as proof",
                report.first_bad_id
            );
            let hit = store.find_agent_audit_by_output_hash(&output_sha256)?;
            let (found, entry_id, tool, decision) = match &hit {
                Some(e) => (
                    true,
                    Some(e.id),
                    Some(e.tool.clone()),
                    Some(e.decision.clone()),
                ),
                None => (false, None, None, None),
            };
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "found": found, "entry_id": entry_id,
                        "tool": tool, "decision": decision,
                        "output_sha256": output_sha256,
                    })
                );
            } else if found {
                println!(
                    "output hash is in the audit chain (entry #{}, {} {})",
                    entry_id.unwrap_or_default(),
                    tool.as_deref().unwrap_or(""),
                    decision.as_deref().unwrap_or("")
                );
            } else {
                println!("output hash NOT in the audit chain — it never passed the scrub");
            }
        }
        AgentLogSubcommand::Anchor { json } => {
            let (confirmed, cid, entries, head) =
                anchor_agent_audit(&get_configured_operators()).await?;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "anchored": true, "operators_confirmed": confirmed,
                        "cid": cid, "entries": entries, "head_hash": head,
                    })
                );
            } else {
                println!(
                    "audit head anchored: {} entries, head {}… confirmed by {} operator(s), checkpoint {}",
                    entries,
                    &head[..head.len().min(16)],
                    confirmed,
                    &cid[..16]
                );
            }
        }
        AgentLogSubcommand::VerifyRemote { json } => {
            use ed25519_dalek::Verifier;
            let record: serde_json::Value = serde_json::from_str(&std::fs::read_to_string(
                get_vault_directory().join("audit_checkpoint.json"),
            )?)?;
            let cid_hex = record["cid"].as_str().unwrap_or_default().to_string();
            let mut cid = [0u8; 32];
            cid.copy_from_slice(&hex::decode(&cid_hex)?);
            let vault_id = store.get_vault_id()?;
            let (_, device_sk, _, _) = store.get_device_state()?;
            let vk = device_sk.verifying_key();
            let pool = configured_operator_pool(get_configured_operators());
            let mut confirmed = 0usize;
            let mut anchored_entries = 0usize;
            let mut anchored_head = String::new();
            for client in pool.clients() {
                let Ok(token) = client.authenticate(&vault_id, &device_sk).await else {
                    continue;
                };
                let Ok(bytes) = client.get_object(&token, &cid).await else {
                    continue;
                };
                if sha2::Sha256::digest(&bytes).as_slice() != cid.as_slice() {
                    continue;
                }
                let Ok(cp) = serde_json::from_slice::<AuditCheckpoint>(&bytes) else {
                    continue;
                };
                let sig_ok = hex::decode(&cp.signature)
                    .ok()
                    .and_then(|b| ed25519_dalek::Signature::from_slice(&b).ok())
                    .map(|sig| {
                        vk.verify(
                            checkpoint_payload(
                                &cp.vault_id,
                                cp.entries,
                                &cp.head_hash,
                                cp.created_at_utc,
                            )
                            .as_bytes(),
                            &sig,
                        )
                        .is_ok()
                    })
                    .unwrap_or(false);
                if sig_ok && cp.vault_id == hex::encode(vault_id) {
                    confirmed += 1;
                    anchored_entries = cp.entries;
                    anchored_head = cp.head_hash.clone();
                }
            }
            let local = store.verify_agent_audit()?;
            ensure!(
                local.ok,
                "local audit chain is BROKEN at entry {:?}; refusing remote comparison",
                local.first_bad_id
            );
            ensure!(confirmed > 0, "no operator holds the anchored checkpoint");
            ensure!(
                local.entries >= anchored_entries,
                "local chain has {} entries but the fleet anchor has {} — local history was truncated or rolled back",
                local.entries,
                anchored_entries
            );
            if anchored_entries > 0 {
                let at_anchor = store.agent_audit_entry_hash_at(anchored_entries)?;
                ensure!(
                    at_anchor.as_deref() == Some(anchored_head.as_str()),
                    "local chain DIVERGES from the fleet anchor at entry #{} — local history was rewritten after anchoring",
                    anchored_entries
                );
            }
            let matches = anchored_entries == local.entries && anchored_head == local.head_hash;
            if json {
                println!(
                    "{}",
                    serde_json::json!({
                        "local_ok": local.ok, "local_entries": local.entries,
                        "anchored_entries": anchored_entries,
                        "operators_confirmed": confirmed,
                        "local_matches_anchor": matches,
                        "local_ahead_by": local.entries.saturating_sub(anchored_entries),
                    })
                );
            } else {
                println!(
                    "local chain: {} ({} entries); fleet anchor: {} entries confirmed by {} operator(s); {}",
                    if local.ok { "OK" } else { "BROKEN" },
                    local.entries,
                    anchored_entries,
                    confirmed,
                    if matches { "local head matches anchor" } else { "local chain is ahead of the anchor (re-run push/anchor to close the gap)" }
                );
            }
        }
        AgentLogSubcommand::Export { out } => {
            let mut entries = store.list_agent_audit(usize::MAX)?;
            entries.reverse();
            let mut buf = String::new();
            for e in &entries {
                buf.push_str(&serde_json::to_string(e)?);
                buf.push('\n');
            }
            match out {
                Some(path) => {
                    let mut f = std::fs::File::create(&path)?;
                    f.write_all(buf.as_bytes())?;
                    println!("exported {} entries to {}", entries.len(), path.display());
                }
                None => print!("{buf}"),
            }
        }
    }
    Ok(())
}
