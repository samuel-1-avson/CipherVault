use super::*;
use ciphervault_crypto::{generate_signing_key, RecoverySecret};
use ciphervault_format::PROTOCOL_VERSION;

#[test]
fn test_scoped_schema_v5_on_fresh_open() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let version: u32 = store
        .conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
    let fks_on: bool = store
        .conn
        .query_row("PRAGMA foreign_keys", [], |row| row.get(0))
        .unwrap();
    assert!(fks_on, "foreign_keys pragma must be ON");
    for table in [
        "scoped_context",
        "scoped_secret_cache",
        "scoped_binding_cache",
    ] {
        let exists: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "missing table {table}");
    }
}

#[test]
fn test_v4_to_v5_migration_recreates_scoped_tables() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    // Simulate a v4 database: drop the v5 tables, rewind the version.
    store
        .conn
        .execute_batch(
            "DROP TABLE scoped_secret_cache;
             DROP TABLE scoped_binding_cache;
             DROP TABLE scoped_context;
             PRAGMA user_version = 4;",
        )
        .unwrap();
    store.run_migrations().unwrap();
    let version: u32 = store
        .conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
    for table in [
        "scoped_context",
        "scoped_secret_cache",
        "scoped_binding_cache",
    ] {
        let exists: bool = store
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                params![table],
                |row| row.get(0),
            )
            .unwrap();
        assert!(exists, "migration did not recreate {table}");
    }
    // Idempotent: a second run is a no-op.
    store.run_migrations().unwrap();
}

#[test]
fn test_scoped_context_roundtrip() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    assert!(store.get_scoped_context().unwrap().is_none());
    store.set_scoped_context("t1", "w1", "p1", "e1").unwrap();
    let ctx = store.get_scoped_context().unwrap().unwrap();
    assert_eq!(ctx.tenant_id, "t1");
    assert_eq!(ctx.workspace_id, "w1");
    assert_eq!(ctx.project_id, "p1");
    assert_eq!(ctx.environment_id, "e1");
    // Overwrite keeps a single row.
    store.set_scoped_context("t1", "w1", "p2", "e9").unwrap();
    let ctx = store.get_scoped_context().unwrap().unwrap();
    assert_eq!(ctx.project_id, "p2");
}

fn cached_meta(secret_id: &str, project: &str, env: &str, name: &str) -> CachedSecretMeta {
    CachedSecretMeta {
        secret_id: secret_id.to_string(),
        tenant_id: "t1".to_string(),
        project_id: project.to_string(),
        environment_id: env.to_string(),
        repository_binding_id: None,
        service_id: None,
        name: name.to_string(),
        secret_type: "key_value".to_string(),
        current_version: 1,
        status: "active".to_string(),
        updated_at_utc: 0,
    }
}

#[test]
fn test_cached_secret_upsert_and_scope_isolation() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    store
        .upsert_cached_secret(&cached_meta("s1", "p1", "e1", "DATABASE_URL"))
        .unwrap();
    // Same scope+name upserts (version bump), no duplicate row.
    let mut bumped = cached_meta("s1", "p1", "e1", "DATABASE_URL");
    bumped.current_version = 2;
    store.upsert_cached_secret(&bumped).unwrap();
    let got = store
        .get_cached_secret("p1", "e1", "DATABASE_URL")
        .unwrap()
        .unwrap();
    assert_eq!(got.current_version, 2);
    // Same name in another environment is a distinct row.
    store
        .upsert_cached_secret(&cached_meta("s2", "p1", "e2", "DATABASE_URL"))
        .unwrap();
    let other = store
        .get_cached_secret("p1", "e2", "DATABASE_URL")
        .unwrap()
        .unwrap();
    assert_eq!(other.secret_id, "s2");
    assert!(store
        .get_cached_secret("p1", "e9", "DATABASE_URL")
        .unwrap()
        .is_none());
}

#[test]
fn test_cached_binding_roundtrip() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let binding = CachedBinding {
        binding_id: "b1".to_string(),
        project_id: "p1".to_string(),
        provider: "github".to_string(),
        external_repo_id: "84920194".to_string(),
        repo_full_name: "acme/pay".to_string(),
        repo_url: "https://example.invalid/acme/pay".to_string(),
        status: "active".to_string(),
        updated_at_utc: 0,
    };
    store.upsert_cached_binding(&binding).unwrap();
    let got = store
        .get_cached_binding("p1", "github", "84920194")
        .unwrap()
        .unwrap();
    assert_eq!(got.repo_full_name, "acme/pay");
    // Rename updates display fields under the same durable id.
    let mut renamed = binding;
    renamed.repo_full_name = "acme/pay-v2".to_string();
    store.upsert_cached_binding(&renamed).unwrap();
    let got = store
        .get_cached_binding("p1", "github", "84920194")
        .unwrap()
        .unwrap();
    assert_eq!(got.repo_full_name, "acme/pay-v2");
    assert!(store
        .get_cached_binding("p1", "github", "00000000")
        .unwrap()
        .is_none());
}

#[test]
fn test_clear_scoped_cache_is_project_scoped() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    store
        .upsert_cached_secret(&cached_meta("s1", "p1", "e1", "A"))
        .unwrap();
    store
        .upsert_cached_secret(&cached_meta("s2", "p2", "e1", "A"))
        .unwrap();
    let removed = store.clear_scoped_cache("p1").unwrap();
    assert_eq!(removed, 1);
    assert!(store.get_cached_secret("p1", "e1", "A").unwrap().is_none());
    assert!(store.get_cached_secret("p2", "e1", "A").unwrap().is_some());
}

#[test]
fn test_lease_receipt_round_trip_and_renew_upsert() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    assert!(store.list_lease_receipts().unwrap().is_empty());
    store
        .record_lease_receipt("lease-1", "https://op1", "ab", 90, 100, 1000, 2000, "sig")
        .unwrap();
    store
        .record_lease_receipt("lease-2", "https://op2", "cd", 30, 50, 1000, 1500, "sig2")
        .unwrap();
    // Soonest-expiring first.
    let listed = store.list_lease_receipts().unwrap();
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].lease_id, "lease-2");
    assert_eq!(listed[1].lease_id, "lease-1");
    assert_eq!(listed[1].term_days, 90);
    // Renewal upserts on the lease id.
    store
        .record_lease_receipt("lease-1", "https://op1", "ab", 180, 100, 1000, 5000, "sig3")
        .unwrap();
    let listed = store.list_lease_receipts().unwrap();
    assert_eq!(listed.len(), 2);
    let renewed = listed.iter().find(|r| r.lease_id == "lease-1").unwrap();
    assert_eq!(renewed.expires_at_utc, 5000);
    assert_eq!(renewed.term_days, 180);
}

#[test]
fn test_derive_head_anchor_salt_roundtrip() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let dev_sk = generate_signing_key();
    let dev_id = [0xBBu8; 32];
    let epoch_key = VaultEpochKey::generate();
    let locator = r.derive_recovery_locator().unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let record = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id: vec![0x77u8; 32],
        parent_snapshot_ids: Vec::new(),
        device_id: dev_id.to_vec(),
        device_counter: 1,
        authority_generation: 1,
        epoch: 1,
        encrypted_manifest_cid: vec![0x22u8; 32],
        encrypted_manifest_len: 100,
        advisory_timestamp_utc: 1000,
        signature: Vec::new(),
    };
    store
        .save_snapshot(&record, b"encrypted_manifest_data", &[])
        .unwrap();
    let head_cid = record.compute_record_cid().unwrap();

    // Derived salt matches an independent KDF computation: the owner
    // can re-derive it from replicated recovery records.
    let salt = store.derive_head_anchor_salt(&head_cid).unwrap();
    assert_eq!(salt, epoch_key.derive_anchor_salt(&head_cid).unwrap());
    // Deterministic across calls; unknown heads stay an error (the
    // anchor falls back to a one-time local salt there).
    assert_eq!(salt, store.derive_head_anchor_salt(&head_cid).unwrap());
    assert!(store.derive_head_anchor_salt(&[0x99u8; 32]).is_err());
}

#[test]
fn test_vault_init_and_tracking() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let dev_sk = generate_signing_key();
    let dev_id = [0xBBu8; 32];
    let epoch_key = VaultEpochKey::generate();

    let locator = r.derive_recovery_locator().unwrap();

    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let fetched_id = store.get_vault_id().unwrap();
    assert_eq!(fetched_id, vault_id);

    let file_id = store.track_file(".env").unwrap();
    let files = store.list_tracked_files().unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(files[0].0, PathBuf::from(".env"));
    assert_eq!(files[0].1, file_id);
}

#[test]
fn test_init_vault_at_epoch_resumes_recovered_epoch() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();

    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let dev_sk = generate_signing_key();
    let dev_id = [0xBBu8; 32];
    let epoch_key = VaultEpochKey::generate();
    let locator = r.derive_recovery_locator().unwrap();

    store
        .init_vault_at_epoch(
            &vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator, 7,
        )
        .unwrap();

    // Device state resumes at epoch 7 with the recovered key; the next
    // rotation mints 8 instead of rewinding to 2.
    let (_, _, _, current_epoch) = store.get_device_state().unwrap();
    assert_eq!(current_epoch, 7);
    let fetched = store.get_epoch_key(7).unwrap();
    assert_eq!(fetched.as_bytes(), epoch_key.as_bytes());
    let (next, _) = store.rotate_epoch_key().unwrap();
    assert_eq!(next, 8);

    // Epoch 0 is rejected: it has no keys by construction.
    let store2 = LocalVaultStore::open(":memory:").unwrap();
    assert!(store2
        .init_vault_at_epoch(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator, 0)
        .is_err());
}

#[test]
fn test_encrypted_key_storage() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
    let locator = r.derive_recovery_locator().unwrap();

    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();

    let dev_sk = generate_signing_key();
    let dev_id = [0xBBu8; 32];
    let epoch_key = VaultEpochKey::generate();

    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    // Inspect raw SQLite blob from database to verify it is NOT plaintext
    let raw_device_sk: Vec<u8> = store
        .conn
        .query_row(
            "SELECT device_signing_key FROM vault_metadata WHERE id = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(raw_device_sk.as_slice(), dev_sk.to_bytes().as_slice());

    let raw_epoch_key: Vec<u8> = store
        .conn
        .query_row(
            "SELECT epoch_key_bytes FROM epoch_keys WHERE epoch = 1",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_ne!(raw_epoch_key.as_slice(), epoch_key.as_bytes().as_slice());

    // get_device_state and get_epoch_key unprotect them seamlessly
    let (_, fetched_sk, _, _) = store.get_device_state().unwrap();
    assert_eq!(fetched_sk.to_bytes(), dev_sk.to_bytes());

    let fetched_epoch = store.get_epoch_key(1).unwrap();
    assert_eq!(fetched_epoch.as_bytes(), epoch_key.as_bytes());

    // Verify descriptors can be fetched
    let (s_pk, e_pk, loc) = store.get_recovery_descriptors().unwrap();
    assert_eq!(s_pk.as_slice(), r_sk.verifying_key().as_bytes());
    assert_eq!(e_pk.as_slice(), r_enc_pk.as_bytes());
    assert_eq!(loc, locator);
}

#[test]
fn pending_upload_summary_tracks_failure_and_completion_without_loading_rows() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    assert_eq!(
        store.pending_upload_summary().unwrap(),
        PendingUploadSummary {
            count: 0,
            failed_count: 0,
            oldest_created_at_utc: None,
        }
    );
    for (id, timestamp) in [(1u8, 300i64), (2, 100), (3, 200)] {
        store.conn.execute(
            "INSERT INTO pending_uploads(snapshot_id, record_cid, created_at_utc) VALUES(?1, ?2, ?3)",
            params![[id; 32].as_slice(), [id + 10; 32].as_slice(), timestamp],
        ).unwrap();
    }
    store
        .record_upload_failure(&[2; 32], "synthetic retry failure")
        .unwrap();
    store
        .record_upload_failure(&[2; 32], "synthetic second failure")
        .unwrap();
    assert_eq!(
        store.pending_upload_summary().unwrap(),
        PendingUploadSummary {
            count: 3,
            failed_count: 1,
            oldest_created_at_utc: Some(100),
        }
    );
    store.mark_upload_completed(&[2; 32]).unwrap();
    assert_eq!(
        store.pending_upload_summary().unwrap(),
        PendingUploadSummary {
            count: 2,
            failed_count: 0,
            oldest_created_at_utc: Some(200),
        }
    );
}

#[test]
fn test_latest_sync_success_reports_newest_ok_only() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    assert!(store.latest_sync_success().unwrap().is_none());
    store
        .record_activity("WATCH_SYNC_FAILED", "boom", "{}")
        .unwrap();
    store
        .record_activity("PUSH_OK", "first", r#"{"snapshot_id":"aa"}"#)
        .unwrap();
    store
        .record_activity("WATCH_SYNC_OK", "second", r#"{"snapshot_id":"bb"}"#)
        .unwrap();
    let latest = store.latest_sync_success().unwrap().unwrap();
    assert_eq!(latest.event_type, "WATCH_SYNC_OK");
    assert!(latest.details_json.contains("bb"));
}

fn agent_audit_store() -> LocalVaultStore {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();
    store
        .init_vault(
            &vault_id,
            &genesis,
            &generate_signing_key(),
            &[0xBBu8; 32],
            &VaultEpochKey::generate(),
            &r.derive_recovery_locator().unwrap(),
        )
        .unwrap();
    store
}

#[test]
fn test_agent_audit_chain_verifies_and_detects_tamper() {
    let store = agent_audit_store();
    let e1 = store
        .append_agent_audit("terminal", "blocked", ".env", r#"{"reason":"secret_read"}"#)
        .unwrap();
    let e2 = store
        .append_agent_audit("ciphervault_run", "approval_requested", "", "{}")
        .unwrap();
    assert_eq!(e2.prev_hash, e1.entry_hash);
    assert_ne!(e1.signature, e2.signature);

    let report = store.verify_agent_audit().unwrap();
    assert!(report.ok, "fresh chain must verify: {report:?}");
    assert_eq!(report.entries, 2);
    assert_eq!(report.head_hash, e2.entry_hash);

    // Tamper with history: verification must fail at that entry.
    store
        .conn
        .execute(
            "UPDATE agent_audit SET path = 'innocent.txt' WHERE id = ?1",
            params![e1.id],
        )
        .unwrap();
    let report = store.verify_agent_audit().unwrap();
    assert!(!report.ok);
    assert_eq!(report.first_bad_id, Some(e1.id));
}

#[test]
fn test_agent_audit_list_newest_first() {
    let store = agent_audit_store();
    store
        .append_agent_audit("read_file", "blocked", "id_rsa", "{}")
        .unwrap();
    store
        .append_agent_audit("terminal", "scrubbed_result", "", r#"{"redactions":2}"#)
        .unwrap();
    let entries = store.list_agent_audit(10).unwrap();
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].tool, "terminal");
    assert_eq!(entries[1].decision, "blocked");
}

#[test]
fn test_agent_audit_find_by_visible_content_hash() {
    // Receipts also carry the hash of the text a person actually
    // sees (a terminal result's `output` field), so a lookup works
    // without reconstructing the tool-result JSON envelope.
    let store = agent_audit_store();
    store
        .append_agent_audit(
            "terminal",
            "scrubbed_result",
            "",
            r#"{"redactions":0,"output_sha256":"envelope01","content_sha256":"visible01"}"#,
        )
        .unwrap();
    let hit = store.find_agent_audit_by_output_hash("visible01").unwrap();
    assert_eq!(hit.map(|e| e.decision), Some("scrubbed_result".to_string()));
    assert!(store
        .find_agent_audit_by_output_hash("envelope01")
        .unwrap()
        .is_some());
    assert!(store
        .find_agent_audit_by_output_hash("visible0")
        .unwrap()
        .is_none());
}

#[test]
fn test_agent_audit_find_by_output_hash() {
    let store = agent_audit_store();
    store
        .append_agent_audit(
            "terminal",
            "scrubbed_result",
            "",
            r#"{"redactions":1,"output_sha256":"abc123"}"#,
        )
        .unwrap();
    let hit = store.find_agent_audit_by_output_hash("abc123").unwrap();
    assert!(hit.is_some());
    assert_eq!(hit.unwrap().decision, "scrubbed_result");
    assert!(store
        .find_agent_audit_by_output_hash("missing0")
        .unwrap()
        .is_none());
}

#[test]
fn test_agent_audit_find_requires_exact_output_field() {
    let store = agent_audit_store();
    // A forged/irrelevant row that merely CONTAINS the digest in
    // another field must not count as scrub proof.
    store
        .conn
        .execute(
            "INSERT INTO agent_audit (created_at_utc, tool, decision, path, detail_json, prev_hash, entry_hash, signature) VALUES (1, 'terminal', 'executed', '', '{\"note\":\"deadbeef\"}', 'x', 'y', 'z')",
            [],
        )
        .unwrap();
    assert!(store
        .find_agent_audit_by_output_hash("deadbeef")
        .unwrap()
        .is_none());
    // Prefix/substring of a real field must not match either.
    store
        .append_agent_audit(
            "terminal",
            "scrubbed_result",
            "",
            r#"{"output_sha256":"deadbeefcafe"}"#,
        )
        .unwrap();
    assert!(store
        .find_agent_audit_by_output_hash("deadbeef")
        .unwrap()
        .is_none());
    assert!(store
        .find_agent_audit_by_output_hash("deadbeefcafe")
        .unwrap()
        .is_some());
}

#[test]
fn test_agent_audit_entry_hash_at_position() {
    let store = agent_audit_store();
    let e1 = store
        .append_agent_audit("terminal", "executed", "a", "{}")
        .unwrap();
    let e2 = store
        .append_agent_audit("terminal", "executed", "b", "{}")
        .unwrap();
    assert_eq!(
        store.agent_audit_entry_hash_at(1).unwrap().as_deref(),
        Some(e1.entry_hash.as_str())
    );
    assert_eq!(
        store.agent_audit_entry_hash_at(2).unwrap().as_deref(),
        Some(e2.entry_hash.as_str())
    );
    assert!(store.agent_audit_entry_hash_at(3).unwrap().is_none());
    assert!(store.agent_audit_entry_hash_at(0).unwrap().is_none());
}

#[test]
fn test_agent_audit_sanitizes_newlines_and_uses_domain_separation() {
    use ed25519_dalek::Signer;
    use sha2::Digest;

    let store = agent_audit_store();
    let e1 = store
        .append_agent_audit("tool\na", "dec\rb", "path\nc", "{\"k\":\"v\"}")
        .unwrap();
    assert!(store.verify_agent_audit().unwrap().ok);

    // Domain-separated signature must match CipherVault-AgentAudit-v1 and NOT
    // another domain or raw pre-domain signing.
    let (_, device_sk, _, _) = store.get_device_state().unwrap();
    let vk = device_sk.verifying_key();
    let sig_bytes: [u8; 64] = hex::decode(&e1.signature).unwrap().try_into().unwrap();
    assert!(ciphervault_crypto::verify_with_domain(
        vk.as_bytes(),
        b"CipherVault-AgentAudit-v1",
        e1.entry_hash.as_bytes(),
        &sig_bytes
    )
    .is_ok());
    assert!(ciphervault_crypto::verify_with_domain(
        vk.as_bytes(),
        b"CipherVault-AuditCheckpoint-v1",
        e1.entry_hash.as_bytes(),
        &sig_bytes
    )
    .is_err());

    // Swapping characters across field boundaries must fail verification
    // because `\n`/`\r` inside fields were sanitized to spaces.
    store
        .conn
        .execute(
            "UPDATE agent_audit SET tool = 'tool', decision = 'a\ndec\rb' WHERE id = ?1",
            params![e1.id],
        )
        .unwrap();
    let bad_split = store.verify_agent_audit().unwrap();
    assert!(!bad_split.ok);
    assert_eq!(bad_split.first_bad_id, Some(e1.id));

    // Restore original fields and verify wrong-domain signature is rejected.
    store
        .conn
        .execute(
            "UPDATE agent_audit SET tool = ?1, decision = ?2 WHERE id = ?3",
            params!["tool\na", "dec\rb", e1.id],
        )
        .unwrap();
    let wrong_domain_sig = hex::encode(ciphervault_crypto::sign_with_domain(
        &device_sk,
        b"CipherVault-AuditCheckpoint-v1",
        e1.entry_hash.as_bytes(),
    ));
    store
        .conn
        .execute(
            "UPDATE agent_audit SET signature = ?1 WHERE id = ?2",
            params![wrong_domain_sig, e1.id],
        )
        .unwrap();
    assert!(!store.verify_agent_audit().unwrap().ok);

    // Legacy raw signature fallback must still verify existing entries.
    let store2 = agent_audit_store();
    let canonical = LocalVaultStore::canonical_audit_preimage(
        "GENESIS", 1700000000, "terminal", "blocked", ".env", "{}",
    );
    let hash = hex::encode(sha2::Sha256::digest(canonical.as_bytes()));
    let (_, sk2, _, _) = store2.get_device_state().unwrap();
    let legacy_sig = hex::encode(sk2.sign(hash.as_bytes()).to_bytes());
    store2
        .conn
        .execute(
            "INSERT INTO agent_audit (created_at_utc, tool, decision, path, detail_json, prev_hash, entry_hash, signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![1700000000i64, "terminal", "blocked", ".env", "{}", "GENESIS", hash, legacy_sig],
        )
        .unwrap();
    assert!(store2.verify_agent_audit().unwrap().ok);
}

#[test]
fn test_latest_key_backup_is_none_until_recorded() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    assert!(store.latest_key_backup().unwrap().is_none());
    store.record_activity("PUSH_OK", "snapshot", "{}").unwrap();
    assert!(store.latest_key_backup().unwrap().is_none());
    store
        .record_activity(
            "KEYBACKUP_OK",
            "sealed backup",
            r#"{"locator":"cc","replicas":2}"#,
        )
        .unwrap();
    let latest = store.latest_key_backup().unwrap().unwrap();
    assert!(latest.details_json.contains("cc"));
}

#[test]
fn test_checkpoint_evidence_storage() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let salt = [1u8; 32];
    let head_cid = [2u8; 32];
    let contract = [3u8; 20];
    let tx_hash = [4u8; 32];

    let evidence = CheckpointEvidence::new(
        salt, head_cid, 42161, contract, tx_hash, 1234567, 1700000000,
    );
    store.save_checkpoint_evidence(&evidence).unwrap();

    let fetched = store.get_checkpoint_evidence(&head_cid).unwrap().unwrap();
    assert_eq!(fetched.commitment, evidence.commitment);
    assert_eq!(fetched.block_number, 1234567);
    assert_eq!(fetched.chain_id, 42161);
    assert!(fetched.verify_commitment());
}

#[test]
fn test_transactional_snapshot_and_pending_uploads() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let snap_id = [0x77u8; 32];
    let record = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: snap_id.to_vec(),
        parent_snapshot_ids: Vec::new(),
        device_id: vec![0x33u8; 32],
        device_counter: 1,
        authority_generation: 1,
        epoch: 1,
        encrypted_manifest_cid: vec![0x22u8; 32],
        encrypted_manifest_len: 100,
        advisory_timestamp_utc: 1000,
        signature: Vec::new(),
    };

    let chunk = ChunkWireObject {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        file_version_id: vec![0x44u8; 32],
        chunk_index: 0,
        total_chunks: 1,
        declared_padded_length: 4,
        key_epoch: 1,
        payload: vec![1, 2, 3, 4],
    };

    store
        .save_snapshot(&record, b"encrypted_manifest_data", &[chunk])
        .unwrap();

    // Verify snapshot is listed in pending_uploads
    let pending = store.list_pending_uploads().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].snapshot_id, snap_id);
    assert_eq!(pending[0].attempts, 0);

    // Record failure
    store
        .record_upload_failure(&snap_id, "Network timeout connecting to operator")
        .unwrap();
    let pending_after_fail = store.list_pending_uploads().unwrap();
    assert_eq!(pending_after_fail[0].attempts, 1);
    assert_eq!(
        pending_after_fail[0].last_error.as_deref(),
        Some("Network timeout connecting to operator")
    );

    // Complete upload
    store.mark_upload_completed(&snap_id).unwrap();
    let pending_after_complete = store.list_pending_uploads().unwrap();
    assert!(pending_after_complete.is_empty());
}

fn queued_snapshot(store: &LocalVaultStore, id: u8, parents: &[u8], at: u64) {
    let record = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: vec![id; 32],
        parent_snapshot_ids: parents.iter().map(|p| vec![*p; 32]).collect(),
        device_id: vec![0x33u8; 32],
        device_counter: u64::from(id),
        authority_generation: 1,
        epoch: 1,
        encrypted_manifest_cid: vec![0x22u8; 32],
        encrypted_manifest_len: 4,
        advisory_timestamp_utc: at,
        signature: Vec::new(),
    };
    store.save_snapshot(&record, b"manifest", &[]).unwrap();
}

#[test]
fn replicated_head_supersedes_queued_ancestors_only() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    // 0xA1 <- 0xA2 <- 0xA3 (replicated); 0xB1 is an unrelated branch.
    queued_snapshot(&store, 0xA1, &[], 1000);
    queued_snapshot(&store, 0xA2, &[0xA1], 1001);
    queued_snapshot(&store, 0xB1, &[], 1002);
    queued_snapshot(&store, 0xA3, &[0xA2], 1003);
    store.mark_upload_completed(&[0xA3; 32]).unwrap();

    let cleared = store.supersede_pending_ancestors(&[0xA3; 32]).unwrap();
    assert_eq!(cleared, 2);
    let left: Vec<[u8; 32]> = store
        .list_pending_uploads()
        .unwrap()
        .into_iter()
        .map(|p| p.snapshot_id)
        .collect();
    assert_eq!(left, vec![[0xB1; 32]], "non-ancestors stay queued");
    // Superseded snapshots keep their rows; only the upload debt goes.
    assert!(store.get_snapshot(&[0xA1; 32]).is_ok());
    assert_eq!(store.supersede_pending_ancestors(&[0xA3; 32]).unwrap(), 0);
}

#[test]
fn test_set_head_transactional_continuity() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let dev_sk = generate_signing_key();
    let dev_id = vec![0x33u8; 32];

    let mut head1 = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: vec![0xAAu8; 32],
        parent_snapshot_ids: Vec::new(),
        closure_digest: vec![0x11u8; 32],
        device_id: dev_id.clone(),
        device_counter: 1,
        authority_generation: None,
        signature: Vec::new(),
    };
    head1.sign(&dev_sk).unwrap();
    store.set_head(&head1).unwrap();

    assert_eq!(
        store.get_active_head().unwrap().unwrap().snapshot_id,
        vec![0xAAu8; 32]
    );

    let mut head2 = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: vec![0xBBu8; 32],
        parent_snapshot_ids: vec![vec![0xAAu8; 32]],
        closure_digest: vec![0x22u8; 32],
        device_id: dev_id,
        device_counter: 2,
        authority_generation: None,
        signature: Vec::new(),
    };
    head2.sign(&dev_sk).unwrap();
    store.set_head(&head2).unwrap();

    assert_eq!(
        store.get_active_head().unwrap().unwrap().snapshot_id,
        vec![0xBBu8; 32]
    );
    let older = store.get_head_for_snapshot(&[0xAA; 32]).unwrap().unwrap();
    assert_eq!(older.device_counter, 1);
    older.verify(dev_sk.verifying_key().as_bytes()).unwrap();
    assert_eq!(
        store.get_head_for_snapshot(&[0xBB; 32]).unwrap().unwrap(),
        head2
    );
    assert!(store.get_head_for_snapshot(&[0xCC; 32]).unwrap().is_none());
}

#[test]
fn prune_removes_rows_sets_and_unreferenced_chunks_only() {
    use ciphervault_format::{RecoveryClosure, RecoverySet};

    let store = LocalVaultStore::open(":memory:").unwrap();
    let record = |id: u8, ts: u64| SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: vec![id; 32],
        parent_snapshot_ids: Vec::new(),
        device_id: vec![0x33u8; 32],
        device_counter: 1,
        authority_generation: 1,
        epoch: 1,
        encrypted_manifest_cid: vec![id; 32],
        encrypted_manifest_len: 3,
        advisory_timestamp_utc: ts,
        signature: Vec::new(),
    };
    let chunk = |payload: &[u8]| ChunkWireObject {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        file_version_id: vec![0x44u8; 32],
        chunk_index: 0,
        total_chunks: 1,
        declared_padded_length: payload.len() as u32,
        key_epoch: 1,
        payload: payload.to_vec(),
    };
    let shared = chunk(b"shared-chunk-bytes");
    let only_old = chunk(b"only-old-chunk-bytes");
    let only_new = chunk(b"only-new-chunk-bytes");
    let shared_cid = shared.compute_cid().unwrap();
    let old_only_cid = only_old.compute_cid().unwrap();
    let new_only_cid = only_new.compute_cid().unwrap();

    let old = record(1, 1000);
    let new = record(2, 2000);
    let old_cid = old.compute_record_cid().unwrap();
    let new_cid = new.compute_record_cid().unwrap();
    store
        .save_snapshot(&old, b"manifest-old", &[shared.clone(), only_old.clone()])
        .unwrap();
    store
        .save_snapshot(&new, b"manifest-new", &[shared.clone(), only_new.clone()])
        .unwrap();
    // Both replicated: the pending guard must not interfere here.
    store.mark_upload_completed(&[1u8; 32]).unwrap();
    store.mark_upload_completed(&[2u8; 32]).unwrap();
    // Crafted recovery sets: old references shared+old-only, new shared+new-only.
    for (cid, chunks) in [
        (old_cid, vec![shared_cid, old_only_cid]),
        (new_cid, vec![shared_cid, new_only_cid]),
    ] {
        let set = RecoverySet {
            closure: RecoveryClosure {
                snapshot_id: vec![0u8; 32],
                snapshot_record_cid: cid.to_vec(),
                manifest_cid: vec![0u8; 32],
                envelope_ids: Vec::new(),
                chunk_cids: chunks.iter().map(|c| c.to_vec()).collect(),
                total_bytes: 0,
            },
            locator: [0u8; 32],
            records: Vec::new(),
        };
        store
            .conn
            .execute(
                "INSERT INTO recovery_sets (head_cid, set_cbor) VALUES (?1, ?2)",
                params![cid.as_slice(), to_canonical_cbor(&set).unwrap()],
            )
            .unwrap();
    }

    // Active head is fail-closed even when explicitly listed.
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vec![0x11u8; 32],
        snapshot_id: new_cid.to_vec(),
        parent_snapshot_ids: Vec::new(),
        closure_digest: vec![0x11u8; 32],
        device_id: vec![0x33u8; 32],
        device_counter: 2,
        authority_generation: None,
        signature: Vec::new(),
    };
    head.sign(&generate_signing_key()).unwrap();
    store.set_head(&head).unwrap();

    let outcome = store.prune_snapshots(&[old_cid, new_cid]).unwrap();
    assert_eq!(outcome.snapshots_removed, 1);
    assert_eq!(outcome.snapshots_skipped_protected, 1);
    assert!(!outcome.chunk_gc_skipped);
    assert_eq!(outcome.chunks_removed, 1);

    // Old rows (both aliases) and its recovery set are gone.
    assert!(store.get_snapshot(&old_cid).is_err());
    assert!(store.get_recovery_set(&old_cid).is_err());
    // New snapshot fully intact.
    assert!(store.get_snapshot(&new_cid).is_ok());
    // Shared + new-only chunks retained; old-only chunk collected.
    let remaining = store.list_all_chunk_cids().unwrap();
    assert!(remaining.contains(&shared_cid));
    assert!(remaining.contains(&new_only_cid));
    assert!(!remaining.contains(&old_only_cid));
}

#[test]
fn certified_hardware_recovery_set_is_valid_and_immutable() {
    use ciphervault_crypto::{HardwareSecurityModule, HsmSlot, SoftwareHsmSimulator};
    use ciphervault_format::{compute_digest, EpochEnvelope, SnapshotManifest};
    let store = LocalVaultStore::open(":memory:").unwrap();
    let recovery = RecoverySecret::generate();
    let root_signer = recovery.derive_recovery_signing_key().unwrap();
    let (recovery_enc_sk, recovery_enc_pk) = recovery.derive_recovery_encryption_keys().unwrap();
    let vault = [41; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        recovery_signing_pk: root_signer.verifying_key().to_bytes().to_vec(),
        recovery_encryption_pk: recovery_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0; 32],
        created_at_utc: 1,
        creation_nonce: vec![0; 32],
        signature: vec![],
    };
    genesis.sign(&root_signer).unwrap();
    let epoch_key = VaultEpochKey::generate();
    store
        .init_vault(
            &vault,
            &genesis,
            &generate_signing_key(),
            &[42; 32],
            &epoch_key,
            &recovery.derive_recovery_locator().unwrap(),
        )
        .unwrap();
    let hsm = SoftwareHsmSimulator::from_seeds(&[43; 32], &[44; 32]);
    let public_key: [u8; 32] = hsm
        .get_public_key(HsmSlot::DigitalSignature)
        .unwrap()
        .try_into()
        .unwrap();
    assert!(store
        .validate_capture_authority_for_key(&public_key, 3)
        .is_err());
    assert!(store.list_snapshots().unwrap().is_empty());
    let mut certificate = DeviceCertificate {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        certificate_id: vec![45; 32],
        device_signing_pk: public_key.to_vec(),
        permissions: 1,
        authority_generation: 3,
        issued_at_utc: 1,
        signature: vec![],
    };
    certificate.sign(&root_signer).unwrap();
    store.save_device_certificate(&certificate).unwrap();
    store
        .validate_capture_authority_for_key(&public_key, 3)
        .unwrap();
    let manifest = SnapshotManifest {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        epoch: 1,
        snapshot_id: vec![46; 32],
        files: vec![],
    };
    let aad = [
        b"CipherVault-Manifest:".as_slice(),
        vault.as_slice(),
        &1u64.to_le_bytes(),
    ]
    .concat();
    let encrypted = ciphervault_crypto::encrypt_chunk(
        &epoch_key.derive_manifest_key(1).unwrap(),
        &to_canonical_cbor(&manifest).unwrap(),
        &aad,
    )
    .unwrap();
    let mut record = SnapshotRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        snapshot_id: manifest.snapshot_id.clone(),
        parent_snapshot_ids: vec![],
        device_id: vec![42; 32],
        device_counter: 1,
        authority_generation: 3,
        epoch: 1,
        encrypted_manifest_cid: compute_digest(&encrypted).to_vec(),
        encrypted_manifest_len: encrypted.len() as u64,
        advisory_timestamp_utc: 1,
        signature: vec![],
    };
    record
        .sign_with_hsm(&hsm, HsmSlot::DigitalSignature)
        .unwrap();
    store.save_snapshot(&record, &encrypted, &[]).unwrap();
    assert!(
        store.prepare_recovery_set(&record).is_err(),
        "Software key must not authorize a hardware record"
    );
    let set = store
        .prepare_recovery_set_with_hsm(&record, &hsm, HsmSlot::DigitalSignature)
        .unwrap();
    let envelope: EpochEnvelope = from_canonical_cbor(&set.records[2]).unwrap();
    envelope.verify(&public_key).unwrap();
    assert_eq!(
        ciphervault_crypto::open_sealed_box(
            &recovery_enc_sk,
            &recovery_enc_pk,
            &envelope.sealed_epoch_key
        )
        .unwrap(),
        epoch_key.as_bytes()
    );
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault.to_vec(),
        snapshot_id: record.compute_record_cid().unwrap().to_vec(),
        parent_snapshot_ids: vec![],
        closure_digest: set.closure.compute_base_closure_digest().unwrap().to_vec(),
        device_id: vec![42; 32],
        device_counter: 1,
        authority_generation: None,
        signature: vec![],
    };
    head.sign_with_hsm(&hsm, HsmSlot::DigitalSignature).unwrap();
    let mut discovery = set.records.clone();
    discovery.push(to_canonical_cbor(&head).unwrap());
    let (selected, cert) = ciphervault_recovery::trust::select_head(
        &discovery,
        &vault,
        root_signer.verifying_key().as_bytes(),
    )
    .unwrap();
    ciphervault_recovery::trust::verify_snapshot(&record, &selected, &cert).unwrap();
    ciphervault_recovery::trust::select_envelope(
        &discovery,
        &record,
        &cert,
        recovery_enc_pk.as_bytes(),
    )
    .unwrap();
    let again = store
        .prepare_recovery_set_with_hsm(&record, &hsm, HsmSlot::DigitalSignature)
        .unwrap();
    let legacy_retry = store.prepare_recovery_set(&record).unwrap();
    assert_eq!(
        to_canonical_cbor(&set).unwrap(),
        to_canonical_cbor(&again).unwrap()
    );
    assert_eq!(
        to_canonical_cbor(&set).unwrap(),
        to_canonical_cbor(&legacy_retry).unwrap()
    );
    assert_eq!(store.recovery_objects(&set).unwrap().len(), 5);
}

#[test]
fn epoch_rotation_advances_current_and_keeps_old_keys() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    let r = RecoverySecret::generate();
    let r_sk = r.derive_recovery_signing_key().unwrap();
    let (_, r_enc_pk) = r.derive_recovery_encryption_keys().unwrap();
    let vault_id = [0xAAu8; 32];
    let mut genesis = GenesisRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        recovery_signing_pk: r_sk.verifying_key().as_bytes().to_vec(),
        recovery_encryption_pk: r_enc_pk.as_bytes().to_vec(),
        policy_digest: vec![0u8; 32],
        created_at_utc: 1000,
        creation_nonce: vec![0u8; 32],
        signature: Vec::new(),
    };
    genesis.sign(&r_sk).unwrap();
    let dev_sk = generate_signing_key();
    let dev_id = [0xBBu8; 32];
    let epoch_key = VaultEpochKey::generate();
    let locator = r.derive_recovery_locator().unwrap();
    store
        .init_vault(&vault_id, &genesis, &dev_sk, &dev_id, &epoch_key, &locator)
        .unwrap();

    let (epoch2, _) = store.rotate_epoch_key().unwrap();
    assert_eq!(epoch2, 2);
    let (_, _, _, current) = store.get_device_state().unwrap();
    assert_eq!(current, 2);
    // Old key still retrievable and distinct.
    let key1 = store.get_epoch_key(1).unwrap();
    let key2 = store.get_epoch_key(2).unwrap();
    assert_ne!(key1.as_bytes(), key2.as_bytes());
    let infos = store.list_epoch_keys().unwrap();
    assert_eq!(infos.len(), 2);
    assert!(infos.iter().all(|info| info.created_at_utc > 0));
    assert!(infos[0].created_at_utc <= infos[1].created_at_utc);
}

#[test]
fn epoch_key_migration_backfills_unknown_stamps() {
    let store = LocalVaultStore::open(":memory:").unwrap();
    // Simulate a pre-migration v2 database with one legacy row.
    store
        .conn
        .execute_batch("ALTER TABLE epoch_keys DROP COLUMN created_at_utc;")
        .unwrap();
    store
        .conn
        .execute(
            "INSERT INTO epoch_keys (epoch, epoch_key_bytes) VALUES (?1, ?2)",
            params![1u64, vec![7u8; 48]],
        )
        .unwrap();
    store.conn.execute("PRAGMA user_version = 2", []).unwrap();
    store.run_migrations().unwrap();
    let version: u32 = store
        .conn
        .query_row("PRAGMA user_version", [], |row| row.get(0))
        .unwrap();
    assert_eq!(version, 5);
    let infos = store.list_epoch_keys().unwrap();
    assert_eq!(infos.len(), 1);
    assert_eq!(infos[0].created_at_utc, 0);
}

#[test]
fn test_open_read_only_never_writes() {
    let path = std::env::temp_dir().join(format!(
        "cv-readonly-{}.db",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    assert!(LocalVaultStore::open_read_only(&path).is_err());
    {
        let _rw = LocalVaultStore::open(&path).unwrap();
    }
    let before = std::fs::read(&path).unwrap();
    {
        let store = LocalVaultStore::open_read_only(&path).unwrap();
        let version: u32 = store
            .conn
            .query_row("PRAGMA user_version", [], |row| row.get(0))
            .unwrap();
        assert_eq!(version, 5);
        assert!(store
            .conn
            .execute("CREATE TABLE probe_readonly(x)", [])
            .is_err());
    }
    let after = std::fs::read(&path).unwrap();
    assert_eq!(before, after);
    std::fs::remove_file(&path).ok();
}
