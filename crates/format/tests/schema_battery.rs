//! Focused test battery for `crates/format/src/schema.rs`.
//!
//! Covers (per audit P1 "schema.rs zero direct tests"):
//! canonical CBOR round-trips + determinism, sign/verify round-trips
//! (incl. HSM paths), and rejection cases (tamper, wrong key, bad
//! lengths, truncated/garbage/oversize input, domain separation).

use ciphervault_crypto::{
    verify_with_domain, HardwareSecurityModule, HsmSlot, SoftwareHsmSimulator,
};
use ciphervault_format::{
    from_canonical_cbor, to_canonical_cbor, CheckpointEvidence, ChunkWireObject, DeviceCertificate,
    EpochEnvelope, FormatError, GenesisRecord, HeadRecord, ManifestFileEntry, PlacementUpdate,
    RecoveryClosure, RecoverySet, SnapshotManifest, SnapshotRecord, MAX_RECORD_SIZE,
    PROTOCOL_VERSION,
};
use ed25519_dalek::SigningKey;

fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn pk_of(sk: &SigningKey) -> [u8; 32] {
    sk.verifying_key().to_bytes()
}

fn sample_genesis(sk: &SigningKey) -> GenesisRecord {
    GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        recovery_signing_pk: pk_of(sk).to_vec(),
        recovery_encryption_pk: vec![0x22; 32],
        policy_digest: vec![0x33; 32],
        created_at_utc: 1_700_000_000,
        creation_nonce: vec![0x44; 32],
        signature: Vec::new(),
    }
}

fn sample_device_cert() -> DeviceCertificate {
    DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        certificate_id: vec![0x55; 32],
        device_signing_pk: vec![0x66; 32],
        permissions: 0b111,
        authority_generation: 3,
        issued_at_utc: 1_700_000_001,
        signature: Vec::new(),
    }
}

fn sample_envelope() -> EpochEnvelope {
    EpochEnvelope {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        epoch: 7,
        recipient_fingerprint: vec![0x77; 32],
        sealed_epoch_key: vec![0x88; 96],
        created_at_utc: 1_700_000_002,
        signer_device_id: vec![0x99; 32],
        signature: Vec::new(),
    }
}

fn sample_chunk() -> ChunkWireObject {
    ChunkWireObject {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        file_version_id: vec![0xAA; 32],
        chunk_index: 2,
        total_chunks: 9,
        declared_padded_length: 4096,
        key_epoch: 7,
        payload: vec![0xBB; 64],
    }
}

fn sample_manifest() -> SnapshotManifest {
    SnapshotManifest {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        epoch: 7,
        snapshot_id: vec![0xCC; 32],
        files: vec![
            ManifestFileEntry {
                file_id: vec![0x01; 16],
                relative_path: "docs/a.txt".to_string(),
                file_version_id: vec![0x02; 32],
                raw_length: 10,
                padded_length: 4096,
                plaintext_sha256: vec![0x03; 32],
                file_version_key: vec![0x04; 32],
                chunk_cids: vec![vec![0x05; 32], vec![0x06; 32]],
                is_deleted: false,
            },
            ManifestFileEntry {
                file_id: vec![0x11; 16],
                relative_path: "gone.bin".to_string(),
                file_version_id: vec![0x12; 32],
                raw_length: 0,
                padded_length: 0,
                plaintext_sha256: vec![0x13; 32],
                file_version_key: vec![0x14; 32],
                chunk_cids: vec![],
                is_deleted: true,
            },
        ],
    }
}

fn sample_snapshot_record() -> SnapshotRecord {
    SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        snapshot_id: vec![0xCC; 32],
        parent_snapshot_ids: vec![vec![0xDD; 32]],
        device_id: vec![0xEE; 32],
        device_counter: 42,
        authority_generation: 3,
        epoch: 7,
        encrypted_manifest_cid: vec![0xFF; 32],
        encrypted_manifest_len: 1234,
        advisory_timestamp_utc: 1_700_000_003,
        signature: Vec::new(),
    }
}

fn sample_head_record() -> HeadRecord {
    HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11; 32],
        snapshot_id: vec![0xCC; 32],
        parent_snapshot_ids: vec![vec![0xDD; 32]],
        closure_digest: vec![0xAB; 32],
        device_id: vec![0xEE; 32],
        device_counter: 43,
        signature: Vec::new(),
    }
}

fn sample_closure() -> RecoveryClosure {
    RecoveryClosure {
        snapshot_id: vec![0xCC; 32],
        snapshot_record_cid: vec![0x01; 32],
        manifest_cid: vec![0x02; 32],
        envelope_ids: vec![vec![0x03; 32]],
        chunk_cids: vec![vec![0x04; 32], vec![0x05; 32]],
        total_bytes: 8192,
    }
}

#[test]
fn protocol_version_is_one() {
    assert_eq!(PROTOCOL_VERSION, 1);
}

#[test]
fn genesis_sign_verify_roundtrip() {
    let sk = signing_key(0x11);
    let mut g = sample_genesis(&sk);
    g.sign(&sk).unwrap();
    assert_eq!(g.signature.len(), 64);
    g.verify().unwrap();
}

#[test]
fn genesis_canonical_roundtrip_deterministic() {
    let sk = signing_key(0x11);
    let mut g = sample_genesis(&sk);
    g.sign(&sk).unwrap();
    let a = to_canonical_cbor(&g).unwrap();
    let b = to_canonical_cbor(&g).unwrap();
    assert_eq!(a, b);
    let back: GenesisRecord = from_canonical_cbor(&a).unwrap();
    assert_eq!(g, back);
    back.verify().unwrap();
}

#[test]
fn genesis_rejects_tampered_body_and_bad_lengths() {
    let sk = signing_key(0x11);
    let mut g = sample_genesis(&sk);
    g.sign(&sk).unwrap();

    let mut tampered = g.clone();
    tampered.vault_id[0] ^= 0xFF;
    assert!(tampered.verify().is_err());

    let mut flipped_sig = g.clone();
    flipped_sig.signature[0] ^= 0x01;
    assert!(flipped_sig.verify().is_err());

    let mut wrong_pk = g.clone();
    wrong_pk.recovery_signing_pk = pk_of(&signing_key(0x22)).to_vec();
    assert!(wrong_pk.verify().is_err());

    let mut short_sig = g.clone();
    short_sig.signature = vec![0u8; 32];
    assert!(matches!(
        short_sig.verify(),
        Err(FormatError::MalformedRecord(_))
    ));

    let mut short_pk = g.clone();
    short_pk.recovery_signing_pk = vec![0u8; 31];
    assert!(matches!(
        short_pk.verify(),
        Err(FormatError::MalformedRecord(_))
    ));

    let unsigned = sample_genesis(&sk);
    assert!(unsigned.verify().is_err());
}

#[test]
fn device_cert_sign_verify_and_roundtrip() {
    let rec = signing_key(0x11);
    let rec_pk = pk_of(&rec);
    let mut c = sample_device_cert();
    c.sign(&rec).unwrap();
    c.verify(&rec_pk).unwrap();
    let bytes = to_canonical_cbor(&c).unwrap();
    assert_eq!(bytes, to_canonical_cbor(&c).unwrap());
    let back: DeviceCertificate = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(c, back);
    back.verify(&rec_pk).unwrap();
}

#[test]
fn device_cert_rejects_tamper_wrong_key_bad_sig() {
    let rec = signing_key(0x11);
    let rec_pk = pk_of(&rec);
    let other_pk = pk_of(&signing_key(0x22));
    let mut c = sample_device_cert();
    c.sign(&rec).unwrap();

    let mut tampered = c.clone();
    tampered.permissions ^= 0xFFFF_FFFF;
    assert!(tampered.verify(&rec_pk).is_err());

    assert!(c.verify(&other_pk).is_err());

    let mut bad = c.clone();
    bad.signature = vec![0u8; 10];
    assert!(matches!(
        bad.verify(&rec_pk),
        Err(FormatError::MalformedRecord(_))
    ));
}

#[test]
fn epoch_envelope_sign_verify_and_roundtrip() {
    let dk = signing_key(0x2A);
    let dpk = pk_of(&dk);
    let mut e = sample_envelope();
    e.sign(&dk).unwrap();
    e.verify(&dpk).unwrap();
    let bytes = to_canonical_cbor(&e).unwrap();
    let back: EpochEnvelope = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(e, back);
    back.verify(&dpk).unwrap();
}

#[test]
fn epoch_envelope_rejects_tamper_and_bad_sig() {
    let dk = signing_key(0x2A);
    let dpk = pk_of(&dk);
    let mut e = sample_envelope();
    e.sign(&dk).unwrap();

    let mut tampered = e.clone();
    tampered.epoch += 1;
    assert!(tampered.verify(&dpk).is_err());

    let mut bad = e.clone();
    bad.signature = vec![0u8; 63];
    assert!(matches!(
        bad.verify(&dpk),
        Err(FormatError::MalformedRecord(_))
    ));
}

#[test]
fn chunk_aad_deterministic_and_field_sensitive() {
    let c = sample_chunk();
    assert_eq!(c.compute_aad(), sample_chunk().compute_aad());

    let mut by_index = c.clone();
    by_index.chunk_index += 1;
    assert_ne!(c.compute_aad(), by_index.compute_aad());

    let mut by_epoch = c.clone();
    by_epoch.key_epoch += 1;
    assert_ne!(c.compute_aad(), by_epoch.compute_aad());

    let mut by_vault = c.clone();
    by_vault.vault_id[0] ^= 0x01;
    assert_ne!(c.compute_aad(), by_vault.compute_aad());

    // Payload is the ciphertext, not a header field: AAD is stable across it.
    let mut by_payload = c.clone();
    by_payload.payload[0] ^= 0x01;
    assert_eq!(c.compute_aad(), by_payload.compute_aad());
}

#[test]
fn chunk_cid_deterministic_and_content_bound() {
    let c = sample_chunk();
    assert_eq!(
        c.compute_cid().unwrap(),
        sample_chunk().compute_cid().unwrap()
    );
    let mut other = c.clone();
    other.payload[0] ^= 0x01;
    assert_ne!(c.compute_cid().unwrap(), other.compute_cid().unwrap());
    let bytes = to_canonical_cbor(&c).unwrap();
    let back: ChunkWireObject = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(c, back);
    assert_eq!(c.compute_cid().unwrap(), back.compute_cid().unwrap());
}

#[test]
fn manifest_snapshot_roundtrip() {
    let m = sample_manifest();
    let bytes = to_canonical_cbor(&m).unwrap();
    let back: SnapshotManifest = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(m, back);

    let mut empty = m.clone();
    empty.files.clear();
    let eb = to_canonical_cbor(&empty).unwrap();
    let eback: SnapshotManifest = from_canonical_cbor(&eb).unwrap();
    assert_eq!(empty, eback);
}

#[test]
fn snapshot_record_sign_verify_and_cid() {
    let dk = signing_key(0x33);
    let dpk = pk_of(&dk);
    let mut r = sample_snapshot_record();
    r.sign(&dk).unwrap();
    r.verify(&dpk).unwrap();
    let cid = r.compute_record_cid().unwrap();
    let bytes = to_canonical_cbor(&r).unwrap();
    let back: SnapshotRecord = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(r, back);
    assert_eq!(cid, back.compute_record_cid().unwrap());

    let mut zero_sig = r.clone();
    zero_sig.signature = vec![0u8; 64];
    assert_ne!(cid, zero_sig.compute_record_cid().unwrap());
}

#[test]
fn snapshot_record_hsm_sign_verify() {
    let hsm = SoftwareHsmSimulator::from_seeds(&[0x07; 32], &[0x09; 32]);
    let pk_vec = hsm.get_public_key(HsmSlot::DigitalSignature).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_vec);
    let mut r = sample_snapshot_record();
    r.sign_with_hsm(&hsm, HsmSlot::DigitalSignature).unwrap();
    r.verify(&arr).unwrap();

    let mut wrong_slot = sample_snapshot_record();
    assert!(wrong_slot
        .sign_with_hsm(&hsm, HsmSlot::KeyManagement)
        .is_err());
}

#[test]
fn snapshot_record_rejects_tamper_and_bad_sig() {
    let dk = signing_key(0x33);
    let dpk = pk_of(&dk);
    let mut r = sample_snapshot_record();
    r.sign(&dk).unwrap();

    let mut tampered = r.clone();
    tampered.device_counter += 1;
    assert!(tampered.verify(&dpk).is_err());

    let mut bad = r.clone();
    bad.signature.pop();
    assert!(matches!(
        bad.verify(&dpk),
        Err(FormatError::MalformedRecord(_))
    ));
}

#[test]
fn head_record_sign_verify_roundtrip_and_rejects() {
    let dk = signing_key(0x44);
    let dpk = pk_of(&dk);
    let mut h = sample_head_record();
    h.sign(&dk).unwrap();
    h.verify(&dpk).unwrap();
    let bytes = to_canonical_cbor(&h).unwrap();
    assert_eq!(bytes, to_canonical_cbor(&h).unwrap());
    let back: HeadRecord = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(h, back);

    let mut tampered = h.clone();
    tampered.closure_digest[0] ^= 0x01;
    assert!(tampered.verify(&dpk).is_err());

    let mut bad = h.clone();
    bad.signature = Vec::new();
    assert!(matches!(
        bad.verify(&dpk),
        Err(FormatError::MalformedRecord(_))
    ));
}

#[test]
fn head_record_hsm_sign_verify() {
    let hsm = SoftwareHsmSimulator::from_seeds(&[0x0A; 32], &[0x0B; 32]);
    let pk_vec = hsm.get_public_key(HsmSlot::DigitalSignature).unwrap();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&pk_vec);
    let mut h = sample_head_record();
    h.sign_with_hsm(&hsm, HsmSlot::DigitalSignature).unwrap();
    h.verify(&arr).unwrap();
}

#[test]
fn checkpoint_commitment_valid_and_tamper_rejected() {
    let salt = [0x51; 32];
    let head_cid = [0x52; 32];
    let ev = CheckpointEvidence::new(
        salt,
        head_cid,
        42161,
        [0x53; 20],
        [0x54; 32],
        99,
        1_700_000_004,
    );
    assert!(ev.verify_commitment());
    assert_eq!(ev.version, PROTOCOL_VERSION);
    assert_eq!(
        CheckpointEvidence::compute_commitment(&salt, &head_cid).as_slice(),
        ev.commitment.as_slice()
    );

    let mut bad_commit = ev.clone();
    bad_commit.commitment[0] ^= 0x01;
    assert!(!bad_commit.verify_commitment());

    let mut bad_salt = ev.clone();
    bad_salt.salt[0] ^= 0x01;
    assert!(!bad_salt.verify_commitment());

    let mut bad_cid = ev.clone();
    bad_cid.head_record_cid[0] ^= 0x01;
    assert!(!bad_cid.verify_commitment());

    let mut short = ev.clone();
    short.salt = vec![0u8; 31];
    assert!(!short.verify_commitment());

    let bytes = to_canonical_cbor(&ev).unwrap();
    let back: CheckpointEvidence = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(ev, back);
    assert!(back.verify_commitment());
}

#[test]
fn recovery_closure_digest_deterministic_and_roundtrip() {
    let c = sample_closure();
    assert_eq!(
        c.compute_base_closure_digest().unwrap(),
        sample_closure().compute_base_closure_digest().unwrap()
    );
    let mut other = c.clone();
    other.total_bytes += 1;
    assert_ne!(
        c.compute_base_closure_digest().unwrap(),
        other.compute_base_closure_digest().unwrap()
    );
    let bytes = to_canonical_cbor(&c).unwrap();
    let back: RecoveryClosure = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(c, back);
}

#[test]
fn recovery_set_roundtrip() {
    let set = RecoverySet {
        closure: sample_closure(),
        locator: [0x61; 32],
        records: vec![vec![1, 2, 3], vec![4, 5]],
    };
    let bytes = to_canonical_cbor(&set).unwrap();
    let back: RecoverySet = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(set.closure, back.closure);
    assert_eq!(set.locator, back.locator);
    assert_eq!(set.records, back.records);
}

#[test]
fn placement_update_roundtrip() {
    let p = PlacementUpdate {
        version: PROTOCOL_VERSION,
        closure_digest: vec![0xAB; 32],
        object_cid: vec![0xCD; 32],
        source_operator: "op-1".to_string(),
        target_operator: "op-2".to_string(),
        updated_at_utc: 1_700_000_005,
        verified_readback: true,
        signature: vec![0xEF; 64],
    };
    let bytes = to_canonical_cbor(&p).unwrap();
    let back: PlacementUpdate = from_canonical_cbor(&bytes).unwrap();
    assert_eq!(p, back);
}

#[test]
fn canonical_rejects_truncated_garbage_empty_and_oversize() {
    let chunk = sample_chunk();
    let bytes = to_canonical_cbor(&chunk).unwrap();

    let cut = &bytes[..bytes.len() / 2];
    assert!(from_canonical_cbor::<ChunkWireObject>(cut).is_err());
    assert!(from_canonical_cbor::<ChunkWireObject>(&[]).is_err());
    assert!(from_canonical_cbor::<ChunkWireObject>(&[0xFF, 0xFF, 0x00, 0x11]).is_err());

    let big = vec![0u8; MAX_RECORD_SIZE + 1];
    assert!(matches!(
        from_canonical_cbor::<SnapshotManifest>(&big),
        Err(FormatError::SizeLimitExceeded { .. })
    ));
}

#[test]
fn canonical_encode_rejects_oversize_payload() {
    let mut chunk = sample_chunk();
    chunk.payload = vec![0xBB; MAX_RECORD_SIZE + 1];
    assert!(matches!(
        to_canonical_cbor(&chunk),
        Err(FormatError::SizeLimitExceeded { .. })
    ));
}

#[test]
fn unsigned_bytes_excludes_signature() {
    let dk = signing_key(0x33);
    let mut r = sample_snapshot_record();
    r.sign(&dk).unwrap();
    let mut other_sig = r.clone();
    other_sig.signature = vec![0x00; 64];
    assert_eq!(
        r.unsigned_bytes().unwrap(),
        other_sig.unsigned_bytes().unwrap()
    );
    assert_ne!(
        to_canonical_cbor(&r).unwrap(),
        to_canonical_cbor(&other_sig).unwrap()
    );

    let rec = signing_key(0x11);
    let mut g = sample_genesis(&rec);
    g.sign(&rec).unwrap();
    let mut g2 = g.clone();
    g2.signature = vec![0x11; 64];
    assert_eq!(g.unsigned_bytes().unwrap(), g2.unsigned_bytes().unwrap());
}

#[test]
fn domain_separation_snapshot_vs_head() {
    let dk = signing_key(0x33);
    let dpk = pk_of(&dk);
    let mut r = sample_snapshot_record();
    r.sign(&dk).unwrap();
    let unsigned = r.unsigned_bytes().unwrap();
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&r.signature);
    assert!(verify_with_domain(&dpk, b"snapshot_record", &unsigned, &sig).is_ok());
    assert!(verify_with_domain(&dpk, b"head_record", &unsigned, &sig).is_err());

    let mut h = sample_head_record();
    h.sign(&dk).unwrap();
    let mut forged = r.clone();
    forged.signature.clone_from(&h.signature);
    assert!(forged.verify(&dpk).is_err());
}
