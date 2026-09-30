//! Recovery authority is rooted exclusively in the offline secret, never in remote records.
use anyhow::{bail, ensure, Context, Result};
use ciphervault_format::{
    from_canonical_cbor, DeviceCertificate, EpochEnvelope, HeadRecord, SnapshotRecord,
    PROTOCOL_VERSION,
};
use std::collections::{HashMap, HashSet};

pub fn select_head(
    records: &[Vec<u8>],
    vault: &[u8; 32],
    root_pk: &[u8; 32],
) -> Result<(HeadRecord, DeviceCertificate)> {
    let mut certs: Vec<DeviceCertificate> = records
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
    certs.sort_by_key(|cert| std::cmp::Reverse(cert.authority_generation));
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
                || head
                    .parent_snapshot_ids
                    .iter()
                    .any(|parent| parent.len() != 32)
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
    // Counters are monotonic only within one device, never a global clock.
    let mut device_counters = HashMap::new();
    let mut authenticated_bindings = HashMap::new();
    let mut graph: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    for (head, cert) in &heads {
        if let Some(previous) =
            authenticated_bindings.insert(head.snapshot_id.clone(), head.clone())
        {
            ensure!(
                previous == *head,
                "Conflicting authenticated head bindings for the same snapshot"
            );
        }
        let counter_key = (
            cert.authority_generation,
            cert.device_signing_pk.clone(),
            head.device_id.clone(),
            head.device_counter,
        );
        if let Some(previous) = device_counters.insert(counter_key, head.snapshot_id.clone()) {
            ensure!(
                previous == head.snapshot_id,
                "Conflicting certified device counters; explicit fork resolution required"
            );
        }
        if let Some(previous) =
            graph.insert(head.snapshot_id.clone(), head.parent_snapshot_ids.clone())
        {
            ensure!(
                previous == head.parent_snapshot_ids,
                "Conflicting authenticated ancestry for the same snapshot"
            );
        }
    }
    let generation = heads
        .iter()
        .map(|(_, cert)| cert.authority_generation)
        .max()
        .unwrap();
    let candidates: Vec<_> = heads
        .into_iter()
        .filter(|(_, cert)| cert.authority_generation == generation)
        .collect();
    let mut nonmaximal = HashSet::new();
    // Iterative, shared traversal avoids both recursion depth and quadratic work
    // on long histories. 1 means active, 2 means completely traversed.
    let mut states = HashMap::new();
    for (head, _) in &candidates {
        let mut pending = vec![(head.snapshot_id.clone(), false)];
        while let Some((node, exiting)) = pending.pop() {
            if exiting {
                states.insert(node, 2);
                continue;
            }
            match states.get(&node) {
                Some(1) => bail!("Cycle in authenticated recovery ancestry"),
                Some(2) => continue,
                _ => {}
            }
            states.insert(node.clone(), 1);
            pending.push((node.clone(), true));
            if let Some(parents) = graph.get(&node) {
                for parent in parents {
                    nonmaximal.insert(parent.clone());
                    pending.push((parent.clone(), false));
                }
            }
        }
    }
    let mut maximal: HashMap<Vec<u8>, (HeadRecord, DeviceCertificate)> = HashMap::new();
    for pair in candidates {
        if !nonmaximal.contains(&pair.0.snapshot_id) {
            maximal.insert(pair.0.snapshot_id.clone(), pair);
        }
    }
    if maximal.len() != 1 {
        bail!("Conflicting certified DAG heads; explicit fork resolution required");
    }
    maximal.into_values().next().context("No recovery head")
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
            && record.parent_snapshot_ids == head.parent_snapshot_ids
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

    fn certified_head(
        root: &ed25519_dalek::SigningKey,
        signer: &ed25519_dalek::SigningKey,
        snapshot: u8,
        counter: u64,
        parents: Vec<u8>,
    ) -> (HeadRecord, Vec<Vec<u8>>) {
        let mut cert = DeviceCertificate {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            certificate_id: vec![snapshot; 32],
            device_signing_pk: signer.verifying_key().to_bytes().to_vec(),
            permissions: 1,
            authority_generation: 1,
            issued_at_utc: 1,
            signature: vec![],
        };
        cert.sign(root).unwrap();
        let mut head = HeadRecord {
            version: PROTOCOL_VERSION,
            vault_id: vec![1; 32],
            snapshot_id: vec![snapshot; 32],
            parent_snapshot_ids: parents.into_iter().map(|p| vec![p; 32]).collect(),
            closure_digest: vec![3; 32],
            device_id: signer.verifying_key().to_bytes().to_vec(),
            device_counter: counter,
            signature: vec![],
        };
        head.sign(signer).unwrap();
        (
            head.clone(),
            vec![
                to_canonical_cbor(&cert).unwrap(),
                to_canonical_cbor(&head).unwrap(),
            ],
        )
    }

    #[test]
    fn descendant_from_new_device_wins_over_older_high_counter() {
        let root = generate_signing_key();
        let a = generate_signing_key();
        let b = generate_signing_key();
        let (_, mut records) = certified_head(&root, &a, 10, 100, vec![]);
        let (new, added) = certified_head(&root, &b, 11, 1, vec![10]);
        records.extend(added);
        assert_eq!(
            select_head(&records, &[1; 32], &root.verifying_key().to_bytes())
                .unwrap()
                .0,
            new
        );
    }

    #[test]
    fn equal_counters_from_different_devices_are_ordered_by_ancestry() {
        let root = generate_signing_key();
        let a = generate_signing_key();
        let b = generate_signing_key();
        let (_, mut records) = certified_head(&root, &a, 10, 1, vec![]);
        let (new, added) = certified_head(&root, &b, 11, 1, vec![10]);
        records.extend(added);
        records.extend(records.clone()); // Operator replicas repeat authenticated records.
        assert_eq!(
            select_head(&records, &[1; 32], &root.verifying_key().to_bytes())
                .unwrap()
                .0,
            new
        );
    }

    #[test]
    fn concurrent_branches_and_authenticated_cycles_fail_closed() {
        let root = generate_signing_key();
        let a = generate_signing_key();
        let b = generate_signing_key();
        let (_, mut records) = certified_head(&root, &a, 10, 100, vec![]);
        let (_, added) = certified_head(&root, &b, 11, 1, vec![]);
        records.extend(added);
        assert!(
            select_head(&records, &[1; 32], &root.verifying_key().to_bytes())
                .unwrap_err()
                .to_string()
                .contains("DAG heads")
        );
        let (_, mut cycle) = certified_head(&root, &a, 10, 1, vec![11]);
        let (_, added) = certified_head(&root, &b, 11, 2, vec![10]);
        cycle.extend(added);
        assert!(select_head(&cycle, &[1; 32], &root.verifying_key().to_bytes()).is_err());
    }

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
