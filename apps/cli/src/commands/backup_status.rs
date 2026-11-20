use anyhow::Result;
use ciphervault_local_store::LocalVaultStore;

/// Locally recorded evidence for the active signed snapshot and recovery drills.
#[derive(Debug, Clone, Default, serde::Serialize)]
pub(crate) struct BackupStatus {
    pub head_record_cid: Option<String>,
    pub replicated_at_utc: Option<i64>,
    pub last_drill_at_utc: Option<i64>,
    pub head_verified_at_utc: Option<i64>,
}

impl BackupStatus {
    pub fn load(store: &LocalVaultStore, head: Option<&[u8; 32]>) -> Result<Self> {
        let replicated_at_utc = match head {
            Some(cid) => match store.get_snapshot_record(cid)? {
                Some(record) => store.snapshot_replicated_at(&record.snapshot_id)?,
                None => None,
            },
            None => None,
        };
        let (last_drill_at_utc, head_verified_at_utc) = store.recovery_drill_times(head)?;
        Ok(Self {
            head_record_cid: head.map(hex::encode),
            replicated_at_utc,
            last_drill_at_utc,
            head_verified_at_utc,
        })
    }

    pub fn replication_label(&self) -> &'static str {
        if self.replicated_at_utc.is_some() {
            "Remote backup verified"
        } else if self.head_record_cid.is_some() {
            "Remote backup unconfirmed"
        } else {
            "No snapshot captured"
        }
    }

    pub fn drill_label(&self) -> &'static str {
        if self.head_verified_at_utc.is_some() {
            "Passed for active snapshot"
        } else if self.last_drill_at_utc.is_some() {
            "Active snapshot unverified"
        } else {
            "No successful drill recorded"
        }
    }
}
