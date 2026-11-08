// Copyright (c) 2026 CipherVault
// SPDX-License-Identifier: Apache-2.0

//! Fleet-join request inbox tests: public submit accepts only
//! self-signed descriptors, resubmits update in place, the inbox is
//! bounded, and listing is sorted. Submitting grants no trust — admission
//! still requires tickets + graduation.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use ciphervault_crypto::generate_signing_key;
use ciphervault_operator::OperatorState;
use ciphervault_storage::types::PeerDescriptor;

static JOIN_COUNTER: AtomicU64 = AtomicU64::new(0);

fn test_state() -> (Arc<OperatorState>, std::path::PathBuf) {
    let slot = JOIN_COUNTER.fetch_add(1, Ordering::SeqCst);
    let dir = std::env::temp_dir().join(format!(
        "ciphervault-joinreq-{}-{}",
        std::process::id(),
        slot
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let state = Arc::new(OperatorState::new(
        "test-operator".to_string(),
        dir.clone(),
        generate_signing_key(),
    ));
    (state, dir)
}

fn descriptor(operator_id: &str) -> PeerDescriptor {
    let key = generate_signing_key();
    PeerDescriptor::new(
        operator_id.to_string(),
        "https://joiner.example:8201".to_string(),
        &key,
    )
}

#[test]
fn submit_accepts_valid_descriptor_and_lists_it() {
    let (state, dir) = test_state();
    let id = state
        .submit_join_request(&descriptor("op-join-1"), "ops@example.com")
        .expect("valid descriptor accepted");
    assert!(!id.is_empty());
    let inbox = state.list_join_requests();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].request_id, id);
    assert_eq!(inbox[0].operator_id, "op-join-1");
    assert_eq!(inbox[0].contact, "ops@example.com");
    assert_eq!(inbox[0].status, "pending");
    assert!(!inbox[0].node_pk_hex.is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn submit_rejects_tampered_and_stale_descriptors() {
    let (state, dir) = test_state();
    // Tampered: valid signature over different bytes.
    let mut bad = descriptor("op-join-bad");
    bad.endpoint = "https://evil.example".to_string();
    assert!(state.submit_join_request(&bad, "").is_err());

    // Garbage key.
    let mut bad_key = descriptor("op-join-badkey");
    bad_key.signing_pk_hex = "not-hex".to_string();
    assert!(state.submit_join_request(&bad_key, "").is_err());

    // Stale timestamp (re-sign to keep the signature valid).
    let key = generate_signing_key();
    let mut stale = PeerDescriptor::new(
        "op-join-stale".to_string(),
        "https://joiner.example:8201".to_string(),
        &key,
    );
    stale.timestamp_utc = 1;
    stale.sign(&key);
    assert!(state.submit_join_request(&stale, "").is_err());

    // Overlong contact.
    assert!(state
        .submit_join_request(&descriptor("op-join-contact"), &"x".repeat(141))
        .is_err());

    assert!(state.list_join_requests().is_empty());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resolve_approves_rejects_and_never_reopens() {
    let (state, dir) = test_state();
    let id = state
        .submit_join_request(&descriptor("op-join-decide"), "")
        .unwrap();

    // Bad decision words rejected.
    assert!(state.resolve_join_request(&id, "maybe").is_err());
    // Unknown id is a not-found.
    assert_eq!(
        state.resolve_join_request("nope", "approved"),
        Err("join request not found".to_string())
    );

    // Approve: status flips, record returned.
    let approved = state.resolve_join_request(&id, "Approved").unwrap();
    assert_eq!(approved.status, "approved");
    assert_eq!(approved.operator_id, "op-join-decide");
    assert!(!approved.node_pk_hex.is_empty());

    // Decided entries never reopen: second resolve conflicts.
    let conflict = state.resolve_join_request(&id, "rejected").unwrap_err();
    assert!(conflict.starts_with("join request already approved"));

    // Rejected path on a fresh entry.
    let id2 = state
        .submit_join_request(&descriptor("op-join-spam"), "")
        .unwrap();
    let rejected = state.resolve_join_request(&id2, "rejected").unwrap();
    assert_eq!(rejected.status, "rejected");

    // Listing still shows both, with final statuses.
    let inbox = state.list_join_requests();
    assert_eq!(inbox.len(), 2);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resubmit_updates_in_place_without_duplicating() {
    let (state, dir) = test_state();
    let id1 = state
        .submit_join_request(&descriptor("op-join-dup"), "first@example.com")
        .unwrap();
    let id2 = state
        .submit_join_request(&descriptor("op-join-dup"), "second@example.com")
        .unwrap();
    assert_eq!(id1, id2, "same operator id keeps its request id");
    let inbox = state.list_join_requests();
    assert_eq!(inbox.len(), 1);
    assert_eq!(inbox[0].contact, "second@example.com");
    let _ = std::fs::remove_dir_all(&dir);
}
