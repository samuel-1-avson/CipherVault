//! Tamper-evident agent-access audit log: what AI-agent tools did
//! around this vault's secrets (blocked reads, approval requests,
//! scrubbed results, writes). Hash-chained and device-signed in the
//! local store; entries carry paths/decisions/counts, never contents.

use anyhow::{bail, Result};
use std::io::Write;

use crate::util::get_vault_store;
use crate::AgentLogSubcommand;

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
