//! Recovery authority is rooted exclusively in the offline secret, never in remote records.
use anyhow::{bail, ensure, Context, Result};
use ciphervault_format::{
    from_canonical_cbor, DeviceCertificate, EpochEnvelope, HeadRecord, SnapshotRecord,
    PROTOCOL_VERSION,
};

pub fn select_head(
    records: &[Vec<u8>],
    vault: &[u8; 32],
    root_pk: &[u8; 32],
) -> Result<(HeadRecord, DeviceCertificate)> {
    let certs: Vec<DeviceCertificate> = records
        .iter()
        .filter_map(|r| from_canonical_cbor(r).ok())
        .filter(|c: &DeviceCertificate| {
            c.version == PROTOCOL_VERSION
                && c.vault_id == vault
                && c.device_signing_pk.len() == 32
                && c.permissions & 1 != 0
                && c.verify(root_pk).is_ok()
        })
        .collect();
    ensure!(
        !certs.is_empty(),
        "No trusted device certificates found; refusing self-authorized recovery"
    );
    let mut heads = Vec::new();
    for bytes in records {
        if let Ok(head) = from_canonical_cbor::<HeadRecord>(bytes) {
            if head.version != PROTOCOL_VERSION
                || head.vault_id != vault
                || head.snapshot_id.len() != 32
            {
                continue;
            }
            for cert in &certs {
                let pk: [u8; 32] = cert.device_signing_pk.as_slice().try_into()?;
                if head.device_id.len() == 32 && head.verify(&pk).is_ok() {
                    heads.push((head.clone(), cert.clone()));
                    break;
                }
            }
        }
    }
    ensure!(
        !heads.is_empty(),
        "No cryptographically authenticated HeadRecords found"
    );
    heads.sort_by_key(|(h, c)| (c.authority_generation, h.device_counter));
    for pair in heads.windows(2) {
        if pair[0].1.authority_generation == pair[1].1.authority_generation
            && pair[0].0.device_counter == pair[1].0.device_counter
            && pair[0].0.snapshot_id != pair[1].0.snapshot_id
        {
            bail!("Conflicting certified heads; explicit fork resolution required");
        }
    }
    heads.pop().context("No recovery head")
}

pub fn verify_snapshot(
    record: &SnapshotRecord,
    head: &HeadRecord,
    cert: &DeviceCertificate,
) -> Result<()> {
    let pk: [u8; 32] = cert.device_signing_pk.as_slice().try_into()?;
    record.verify(&pk)?;
    ensure!(
        record.version == PROTOCOL_VERSION
            && record.vault_id == head.vault_id
            && record.device_id == head.device_id
            && record.device_counter == head.device_counter
            && record.authority_generation == cert.authority_generation
            && record.compute_record_cid()?.as_slice() == head.snapshot_id,
        "Snapshot authority or head binding mismatch"
    );
    Ok(())
}

pub fn select_envelope(
    records: &[Vec<u8>],
    record: &SnapshotRecord,
    cert: &DeviceCertificate,
    recipient: &[u8; 32],
) -> Result<EpochEnvelope> {
    let pk: [u8; 32] = cert.device_signing_pk.as_slice().try_into()?;
    records
        .iter()
        .filter_map(|r| from_canonical_cbor::<EpochEnvelope>(r).ok())
        .find(|e| {
            e.version == PROTOCOL_VERSION
                && e.vault_id == record.vault_id
                && e.epoch == record.epoch
                && e.signer_device_id == record.device_id
                && e.recipient_fingerprint == recipient
                && e.verify(&pk).is_ok()
        })
        .context("No authenticated epoch envelope for this snapshot and recovery key")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ciphervault_crypto::{generate_signing_key, RecoverySecret};
    use ciphervault_format::to_canonical_cbor;

    #[test]
    fn refuses_self_authorization_and_invalid_certificates() {
        let root = RecoverySecret::generate()
            .derive_recovery_signing_key()
            .unwrap();
        let attacker = generate_signing_key();
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            snapshot_id: vec![2; 32],
            parent_snapshot_ids: vec![],
            closure_digest: vec![3; 32],
            device_id: attacker.verifying_key().to_bytes().to_vec(),
            device_counter: u64::MAX,
            signature: vec![],
        };
        head.sign(&attacker).unwrap();
        let head_bytes = to_canonical_cbor(&head).unwrap();
        assert!(select_head(
            std::slice::from_ref(&head_bytes),
            &[1; 32],
            &root.verifying_key().to_bytes()
        )
        .is_err());
        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            certificate_id: vec![4; 32],
            device_signing_pk: attacker.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: vec![],
        };
        cert.sign(&attacker).unwrap();
        assert!(select_head(
            &[head_bytes.clone(), to_canonical_cbor(&cert).unwrap()],
            &[1; 32],
            &root.verifying_key().to_bytes()
        )
        .is_err());
        cert.sign(&root).unwrap();
        assert!(select_head(
            &[head_bytes.clone(), to_canonical_cbor(&cert).unwrap()],
            &[1; 32],
            &root.verifying_key().to_bytes()
        )
        .is_ok());
        cert.permissions = 0;
        cert.sign(&root).unwrap();
        assert!(select_head(
            &[head_bytes, to_canonical_cbor(&cert).unwrap()],
            &[1; 32],
            &root.verifying_key().to_bytes()
        )
        .is_err());
    }

    #[test]
    fn rejects_tampered_envelopes_and_snapshot_bindings() {
        let sk = generate_signing_key();
        let cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            certificate_id: vec![4; 32],
            device_signing_pk: sk.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: vec![],
        };
        let mut record = SnapshotRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            snapshot_id: vec![2; 32],
            parent_snapshot_ids: vec![],
            device_id: vec![9; 32],
            device_counter: 1,
            authority_generation: 1,
            epoch: 1,
            encrypted_manifest_cid: vec![5; 32],
            encrypted_manifest_len: 0,
            advisory_timestamp_utc: 1,
            signature: vec![],
        };
        record.sign(&sk).unwrap();
        let head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            snapshot_id: record.compute_record_cid().unwrap().to_vec(),
            parent_snapshot_ids: vec![],
            closure_digest: vec![3; 32],
            device_id: vec![9; 32],
            device_counter: 1,
            signature: vec![],
        };
        assert!(verify_snapshot(&record, &head, &cert).is_ok());
        let mut wrong = record.clone();
        wrong.authority_generation = 2;
        wrong.sign(&sk).unwrap();
        assert!(verify_snapshot(&wrong, &head, &cert).is_err());
        let mut envelope = EpochEnvelope {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            epoch: 1,
            recipient_fingerprint: vec![6; 32],
            sealed_epoch_key: vec![7; 80],
            created_at_utc: 1,
            signer_device_id: vec![9; 32],
            signature: vec![],
        };
        envelope.sign(&sk).unwrap();
        assert!(select_envelope(
            &[to_canonical_cbor(&envelope).unwrap()],
            &record,
            &cert,
            &[6; 32]
        )
        .is_ok());
        envelope.sealed_epoch_key[0] ^= 1;
        assert!(select_envelope(
            &[to_canonical_cbor(&envelope).unwrap()],
            &record,
            &cert,
            &[6; 32]
        )
        .is_err());
    }
}
