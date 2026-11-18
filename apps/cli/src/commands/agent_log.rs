//! Tamper-evident agent-access audit log: what AI-agent tools did
//! around this vault's secrets (blocked reads, approval requests,
//! scrubbed results, writes). Hash-chained and device-signed in the
//! local store; entries carry paths/decisions/counts, never contents.

use anyhow::{bail, ensure, Result};
use sha2::Digest;
use std::io::Write;

use crate::util::{
    configured_operator_pool, get_configured_operators, get_vault_directory, get_vault_store,
};
use crate::AgentLogSubcommand;

const AUDIT_CHECKPOINT_SIG_DOMAIN: &[u8] = b"CipherVault-AuditCheckpoint-v1";

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

fn verify_checkpoint_signature(vk: &ed25519_dalek::VerifyingKey, cp: &AuditCheckpoint) -> bool {
    let payload = checkpoint_payload(&cp.vault_id, cp.entries, &cp.head_hash, cp.created_at_utc);
    let Some(sig_bytes) = hex::decode(&cp.signature)
        .ok()
        .and_then(|b| <[u8; 64]>::try_from(b.as_slice()).ok())
    else {
        return false;
    };
    if ciphervault_crypto::verify_with_domain(
        vk.as_bytes(),
        AUDIT_CHECKPOINT_SIG_DOMAIN,
        payload.as_bytes(),
        &sig_bytes,
    )
    .is_ok()
    {
        return true;
    }
    // Legacy backwards-compatibility fallback for pre-domain checkpoints.
    if vk.is_weak() {
        return false;
    }
    let sig = ed25519_dalek::Signature::from_bytes(&sig_bytes);
    vk.verify_strict(payload.as_bytes(), &sig).is_ok()
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
        let payload = checkpoint_payload(&vault_hex, report.entries, &report.head_hash, ts);
        let signature = hex::encode(ciphervault_crypto::sign_with_domain(
            &device_sk,
            AUDIT_CHECKPOINT_SIG_DOMAIN,
            payload.as_bytes(),
        ));
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

fn sanitize_audit_field(value: &str) -> String {
    value.replace(['\n', '\r'], " ")
}

fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut k_pad = [0u8; 64];
    if key.len() > 64 {
        let digest: [u8; 32] = sha2::Sha256::digest(key).into();
        k_pad[..32].copy_from_slice(&digest);
    } else {
        k_pad[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k_pad[i];
        opad[i] ^= k_pad[i];
    }
    let mut inner = sha2::Sha256::new();
    inner.update(ipad);
    inner.update(msg);
    let inner_hash = inner.finalize();

    let mut outer = sha2::Sha256::new();
    outer.update(opad);
    outer.update(inner_hash);
    outer.finalize().into()
}

pub(crate) fn verify_audit_caller_hmac(
    tool: &str,
    decision: &str,
    path: &str,
    detail: &str,
    hmac_hex: Option<&str>,
) -> Result<()> {
    let key_raw = match std::env::var("CIPHERVAULT_AUDIT_HMAC_KEY") {
        Ok(v) if !v.trim().is_empty() => v,
        _ => {
            if std::env::var("CIPHERVAULT_REQUIRE_AUDIT_HMAC").as_deref() == Ok("1") {
                bail!("agent-log record rejected: CIPHERVAULT_AUDIT_HMAC_KEY is required");
            }
            return Ok(());
        }
    };
    let key_bytes = if key_raw.len() == 64 && key_raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        hex::decode(&key_raw)?
    } else {
        key_raw.into_bytes()
    };
    let provided_hex = hmac_hex
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!("agent-log record rejected: missing --hmac for CIPHERVAULT_AUDIT_HMAC_KEY")
        })?;
    let provided = hex::decode(provided_hex)
        .map_err(|_| anyhow::anyhow!("agent-log record rejected: malformed --hmac hex"))?;
    let msg = format!(
        "{}\n{}\n{}\n{}",
        sanitize_audit_field(tool),
        sanitize_audit_field(decision),
        sanitize_audit_field(path),
        sanitize_audit_field(detail)
    );
    let expected = hmac_sha256(&key_bytes, msg.as_bytes());
    let mut diff = (provided.len() ^ expected.len()) as u8;
    for (a, b) in provided.iter().zip(expected.iter()) {
        diff |= a ^ b;
    }
    if diff != 0 {
        bail!("agent-log record rejected: HMAC verification failed");
    }
    Ok(())
}

pub(crate) async fn cmd_agent_log(sub: AgentLogSubcommand) -> Result<()> {
    let store = get_vault_store()?;
    match sub {
        AgentLogSubcommand::Record {
            tool,
            decision,
            path,
            detail,
            hmac,
        } => {
            verify_audit_caller_hmac(&tool, &decision, &path, &detail, hmac.as_deref())?;
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
                let sig_ok = verify_checkpoint_signature(&vk, &cp);
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

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    #[test]
    fn audit_checkpoint_uses_domain_separation_with_legacy_fallback() {
        let sk = ciphervault_crypto::generate_signing_key();
        let vk = sk.verifying_key();
        let payload = checkpoint_payload("aa".repeat(32).as_str(), 3, "bb".repeat(32).as_str(), 1700);
        let domain_sig = hex::encode(ciphervault_crypto::sign_with_domain(
            &sk,
            AUDIT_CHECKPOINT_SIG_DOMAIN,
            payload.as_bytes(),
        ));
        let cp = AuditCheckpoint {
            kind: "agent-audit-checkpoint".to_string(),
            vault_id: "aa".repeat(32),
            entries: 3,
            head_hash: "bb".repeat(32),
            created_at_utc: 1700,
            signature: domain_sig,
        };
        assert!(verify_checkpoint_signature(&vk, &cp));

        // Tampering with entries breaks verification.
        let mut tampered = AuditCheckpoint {
            entries: 4,
            ..AuditCheckpoint {
                kind: cp.kind.clone(),
                vault_id: cp.vault_id.clone(),
                entries: cp.entries,
                head_hash: cp.head_hash.clone(),
                created_at_utc: cp.created_at_utc,
                signature: cp.signature.clone(),
            }
        };
        assert!(!verify_checkpoint_signature(&vk, &tampered));

        // Wrong domain signature must fail verification.
        tampered.entries = 3;
        tampered.signature = hex::encode(ciphervault_crypto::sign_with_domain(
            &sk,
            b"CipherVault-AgentAudit-v1",
            payload.as_bytes(),
        ));
        assert!(!verify_checkpoint_signature(&vk, &tampered));

        // Legacy raw Ed25519 signature still verifies for backwards compatibility.
        let legacy_cp = AuditCheckpoint {
            kind: "agent-audit-checkpoint".to_string(),
            vault_id: "aa".repeat(32),
            entries: 3,
            head_hash: "bb".repeat(32),
            created_at_utc: 1700,
            signature: hex::encode(sk.sign(payload.as_bytes()).to_bytes()),
        };
        assert!(verify_checkpoint_signature(&vk, &legacy_cp));
    }

    #[tokio::test]
    async fn audit_caller_hmac_validates_and_rejects_forgeries() {
        let _guard = crate::util::TEST_PROCESS_STATE.lock().await;
        let prev_key = std::env::var_os("CIPHERVAULT_AUDIT_HMAC_KEY");
        let prev_req = std::env::var_os("CIPHERVAULT_REQUIRE_AUDIT_HMAC");
        let key = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        std::env::set_var("CIPHERVAULT_AUDIT_HMAC_KEY", key);
        std::env::set_var("CIPHERVAULT_REQUIRE_AUDIT_HMAC", "1");

        let tag = hex::encode(hmac_sha256(
            &hex::decode(key).unwrap(),
            b"terminal blocked .env {\"reason\":\"secret\"}",
        ));
        // Wrong separator (space instead of newline) fails.
        assert!(verify_audit_caller_hmac(
            "terminal",
            "blocked",
            ".env",
            "{\"reason\":\"secret\"}",
            Some(&tag),
        )
        .is_err());

        let valid_tag = hex::encode(hmac_sha256(
            &hex::decode(key).unwrap(),
            b"terminal\nblocked\n.env\n{\"reason\":\"secret\"}",
        ));
        assert!(verify_audit_caller_hmac(
            "terminal",
            "blocked",
            ".env",
            "{\"reason\":\"secret\"}",
            Some(&valid_tag),
        )
        .is_ok());
        assert!(
            verify_audit_caller_hmac("terminal", "blocked", ".env", "{}", None).is_err()
        );

        match prev_key {
            Some(v) => std::env::set_var("CIPHERVAULT_AUDIT_HMAC_KEY", v),
            None => std::env::remove_var("CIPHERVAULT_AUDIT_HMAC_KEY"),
        }
        match prev_req {
            Some(v) => std::env::set_var("CIPHERVAULT_REQUIRE_AUDIT_HMAC", v),
            None => std::env::remove_var("CIPHERVAULT_REQUIRE_AUDIT_HMAC"),
        }
    }
}
