# CipherVault Automated Verification & Security Audit Report

**Generated:** 2026-11-06 23:43:15Z  
**Overall Result:** 🟢 ALL INVARIANTS VERIFIED (PASS)  
**Total Execution Time:** 269482 ms  

## 1. Executive Invariant Verification Matrix

| Verification Module | Target Subsystem | Status | Duration |
|---|---|:---:|:---:|
| **Galois Field Constant-Time KAT (GF(2^8) Axioms & Timing)** | `ciphervault-crypto` | ✅ PASS | 2497 ms |
| **Cryptographic Primitives Invariants (Shamir 3-of-5, AEAD, KDF)** | `ciphervault-crypto` | ✅ PASS | 31351 ms |
| **Chunk Protocol v2 Deduplication & Domain Isolation** | `ciphervault-snapshot` | ✅ PASS | 5404 ms |
| **Section 20 T-901 Audit Privacy Rule (Canary Gate & Redactor)** | `ciphervault-redact` | ✅ PASS | 2180 ms |
| **Recovery Custody & Zero-Dependency Alerting Dispatcher** | `scripts/recovery` | ✅ PASS | 7222 ms |
| **Kubernetes CSI Ephemeral Zero-Disk In-Memory Provider** | `deploy/kubernetes` | ✅ PASS | 1038 ms |
| **HA Clustered Database Storage & Replication Routing** | `ciphervault-account` | ✅ PASS | 33735 ms |
| **Model Context Protocol (MCP) AI Coding Agent Server** | `services/mcp` | ✅ PASS | 2977 ms |
| **Local AI Guardian Continuous Runtime Sprawl Scanner** | `ciphervault-agent` | ✅ PASS | 13824 ms |
| **Autonomous Swarm Predictive Healer & Telemetry Engine** | `ciphervault-maintenance` | ✅ PASS | 50538 ms |
| **Sovereign Blockchain PoA Consensus & Light Client Engine** | `ciphervault-chain` | ✅ PASS | 8727 ms |
| **Local Vault Guardian Deep Secret Leak Pre-commit Scan** | `ciphervault-cli` | ✅ PASS | 52347 ms |
| **Agentic AI In-Memory Execution Bridge & Redaction Invariant** | `ciphervault-cli` | ✅ PASS | 57579 ms |

## 2. Cryptographic Specification Checksums

| Document | Status | Size | SHA-256 Digest |
|---|:---:|:---:|---|
| `docs/CRYPTOGRAPHIC_AUDIT_SPECIFICATION.md` | Present | 10101 B | `761197dba06c400675fd69b99155fbe31a9e4fa0c5eceb89fde2802373d3b81a` |
| `docs/CURRENT_SECURITY_GUARANTEES.md` | Present | 12938 B | `1a4643d53b7d12ccde2004d0e54b2ca8188e9a6eed5be2ed8308dd1bc1fa4f0c` |
| `crates/snapshot/CHUNK_PROTOCOL_V2.md` | Present | 3995 B | `2f16cf327118657241bba8f4270b1ce155b4669021a17b0974610c243d6c9e66` |

## 3. Detailed Check Summaries

### Galois Field Constant-Time KAT (GF(2^8) Axioms & Timing)
- **Status:** PASS
- **Execution Time:** 2497 ms
```text
running 4 tests
test test_constant_time_gf_mul_matches_reference_kat_exhaustive ... ok
test test_gf_algebraic_field_axioms_exhaustive ... ok
test test_gf_distributivity_and_commutativity ... ok
test test_constant_time_execution_profile ... ok

test result: ok. 4 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.69s
```

### Cryptographic Primitives Invariants (Shamir 3-of-5, AEAD, KDF)
- **Status:** PASS
- **Execution Time:** 31351 ms
```text
running 38 tests
test envelope::tests::dek_explicit_zeroize_scrubs ... ok
test keys::tests::test_zeroize_memory_scrubbing ... ok
test aead::tests::test_detached_nonce_roundtrip ... ok
test aead::tests::test_wrong_aad_fails ... ok
test chunk_v2::tests::domains_vaults_epochs_and_secrets_are_isolated ... ok
test aead::tests::test_tampered_ciphertext_fails ... ok
test aead::tests::test_encrypt_decrypt_roundtrip ... ok
test envelope::tests::scope_aad_layout_is_fixed_and_unambiguous ... ok
test envelope::tests::seal_open_roundtrip_and_cross_scope_replay_fails ... ok
test envelope::tests::wrap_unwrap_roundtrip_and_kek_mismatch_fails ... ok
test kdf::tests::test_kdf_determinism ... ok
test keys::tests::test_key_hierarchy_derivation ... ok
test hsm::tests::test_software_hsm_ecdh_agreement ... ok
test piv::tests::test_apdu_dynamic_auth_sign_template ... ok
test piv::tests::test_apdu_serialization_select_piv ... ok
test piv::tests::test_dynamic_auth_tag_extraction ... ok
test piv::tests::test_apdu_serialization_verify_pin ... ok
test piv::tests::test_response_apdu_parsing_and_status ... ok
test piv::tests::test_slot_metadata_tlv_parsing ... ok
test sealed_box::tests::low_order_recipients_cannot_receive_publicly_decryptable_boxes ... ok
test piv::tests::test_pin_cache_lifecycle_and_env_resolution ... ok
test sealed_box::tests::low_order_ephemeral_cannot_forge_an_authenticated_box ... ok
test shamir::tests::test_shamir_2_of_3_reconstruction ... ok
test shamir::tests::test_gf_mul_and_inv .
```

### Chunk Protocol v2 Deduplication & Domain Isolation
- **Status:** PASS
- **Execution Time:** 5404 ms
```text
running 20 tests
test fastcdc::tests::test_fastcdc_empty_and_sub_min ... ok
test chunker::tests::test_chunking_small_file_padding ... ok
test engine::tests::legacy_snapshot_still_decrypts_without_changing_v1_wire_addresses ... ok
test chunker::tests::test_content_defined_chunk_deduplication_and_isolation ... ok
test fastcdc::tests::test_fastcdc_determinism ... ok
test engine::tests::test_restore_bounds_enforcement_and_rejection ... ok
test fastcdc::tests::test_chunk_profiles_select_expected_sizes ... ok
test fastcdc::tests::test_fastcdc_bounds_enforcement ... ok
test engine::tests::test_decrypt_snapshot_in_memory ... ok
test engine::tests::test_atomic_all_or_nothing_restore_on_corruption ... ok
test engine::tests::capture_bounds_checked_before_read_and_tombstone_hashes_are_reported ... ok
test restore::tests::unsafe_late_destination_never_publishes_earlier_files ... ok
test fastcdc::tests::test_fastcdc_boundary_shift_resistance ... ok
test engine::tests::capture_write_gate_defaults_to_v2_and_supports_legacy_v1_opt_out ... ok
test restore::tests::publication_failure_restores_all_originals ... ok
test restore::tests::interrupted_publication_is_recoverable_and_respects_external_changes ... ok
test restore::tests::published_secret_has_restrictive_windows_acl ... ok
test engine::tests::v2_reordered_manifest_chunks_and_unknown_wire_versions_are_rejected ... ok
test chunker::tests::v2_changed_file_reuses_encrypted_chunks_and_hides_candidate_digest ... ok
test engine::tests::v2_repea
```

### Section 20 T-901 Audit Privacy Rule (Canary Gate & Redactor)
- **Status:** PASS
- **Execution Time:** 2180 ms
```text
running 8 tests
test tests::bare_prefix_without_payload_passes_through ... ok
test tests::bearer_scheme_kept_token_redacted ... ok
test tests::credential_assignments_keep_key_redact_value ... ok
test tests::identifier_lookalikes_pass_through ... ok
test tests::redaction_is_idempotent ... ok
test tests::private_pem_redacted_public_pem_kept ... ok
test tests::scope_token_redacts_payload_but_keeps_prefix ... ok
test tests::unicode_passthrough ... ok

test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 2 tests
test crates\redact\src\lib.rs - redact_text (line 59) ... ok
test crates\redact\src\lib.rs - contains_secret_shaped (line 102) ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1.16s
```

### Recovery Custody & Zero-Dependency Alerting Dispatcher
- **Status:** PASS
- **Execution Time:** 7222 ms
```text
................C:\Users\samue\OneDrive\Desktop\projects\CipherVault\tests\recovery\test_account_custody.py:473: ResourceWarning: unclosed file <_io.BufferedReader name=4>
  with self.assertRaisesRegex(custody.CustodyError, "timed out"):
ResourceWarning: Enable tracemalloc to get the object allocation traceback
.............s....................
----------------------------------------------------------------------
Ran 50 tests in 6.024s

OK (skipped=1)
```

### Kubernetes CSI Ephemeral Zero-Disk In-Memory Provider
- **Status:** PASS
- **Execution Time:** 1038 ms
```text
....
----------------------------------------------------------------------
Ran 4 tests in 0.664s

OK
```

### HA Clustered Database Storage & Replication Routing
- **Status:** PASS
- **Execution Time:** 33735 ms
```text
running 3 tests
test ha_store::tests::test_replication_lag_health_detection ... ok
test ha_store::tests::test_local_sqlite_lifecycle ... ok
test ha_store::tests::test_read_replica_rejects_writes ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 164 filtered out; finished in 0.02s
```

### Model Context Protocol (MCP) AI Coding Agent Server
- **Status:** PASS
- **Execution Time:** 2977 ms
```text
.....
----------------------------------------------------------------------
Ran 5 tests in 2.306s

OK
```

### Local AI Guardian Continuous Runtime Sprawl Scanner
- **Status:** PASS
- **Execution Time:** 13824 ms
```text
running 2 tests
test guardian::tests::test_guardian_detects_secret_shaped_content ... ok
test guardian::tests::test_guardian_detects_untracked_secret_file ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.01s
```

### Autonomous Swarm Predictive Healer & Telemetry Engine
- **Status:** PASS
- **Execution Time:** 50538 ms
```text
running 3 tests
test predictive_healer::tests::test_nominal_durability_score ... ok
test predictive_healer::tests::test_critical_healing_on_replica_loss ... ok
test predictive_healer::tests::test_predictive_healing_on_degraded_node_latency ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 2 filtered out; finished in 0.00s
```

### Sovereign Blockchain PoA Consensus & Light Client Engine
- **Status:** PASS
- **Execution Time:** 8727 ms
```text
running 3 tests
test merkle::tests::test_empty_merkle_tree ... ok
test merkle::tests::test_single_leaf_merkle_tree ... ok
test merkle::tests::test_multi_leaf_merkle_tree_and_proofs ... ok

test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s


running 2 tests
test test_byzantine_fault_tolerance_rejection ... ok
test test_sovereign_blockchain_full_lifecycle ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.22s


running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
running 1 test
test test_sovereign_chain_end_to_end_anchoring_and_light_verification ... ok

test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.35s
```

### Local Vault Guardian Deep Secret Leak Pre-commit Scan
- **Status:** PASS
- **Execution Time:** 52347 ms
```text
{
  "deep_scan": true,
  "fixed_files": [],
  "status": "clean",
  "violations": [],
  "violations_count": 0
}
```

### Agentic AI In-Memory Execution Bridge & Redaction Invariant
- **Status:** PASS
- **Execution Time:** 57579 ms
```text
running 2 tests
test test_agentic_ai_json_redaction_and_guardian_hook ... ok
test test_run_secret_injection_and_zero_disk_execution ... ok

test result: ok. 2 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 7.08s
```

---
## 4. Auditor Sign-Off Template

- [ ] **Track A (Pen-Test):** Local secret boundaries, injection safety, and zero-disk execution confirmed.
- [ ] **Track B (Crypto):** Galois field axioms, constant-time properties, and chunk v2 derivations verified.

**Auditor Signature:** ___________________________  
**Date:** ___________________________  
