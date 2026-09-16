use ciphervault_operator::OperatorState;
use std::sync::Arc;

/// R8: concurrent uploads for distinct CIDs must stay consistent now that the
/// global `io_lock` is replaced by per-key striped locks, and same-key
/// writers must still serialize on one stripe.
#[test]
fn concurrent_puts_across_keys_stay_consistent() {
    let root = std::env::temp_dir().join(format!("cv-io-shard-{}", rand::random::<u128>()));
    let state = Arc::new(OperatorState::new(
        "shard-test".into(),
        root.clone(),
        ciphervault_crypto::generate_signing_key(),
    ));

    let mut handles = Vec::new();
    for thread in 0..8u32 {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            for item in 0..32u32 {
                let mut payload =
                    format!("shard payload thread={thread} item={item}").into_bytes();
                payload.extend(vec![thread as u8; 1024]);
                let cid_hex = hex::encode(ciphervault_format::compute_digest(&payload));
                state.put_object(&cid_hex, &payload).unwrap();
                // Same-key concurrent writers serialize on one stripe.
                state.put_object(&cid_hex, &payload).unwrap();
                let read_back = state.get_object(&cid_hex).expect("stored object reads back");
                assert_eq!(read_back, payload);
            }
        }));
    }
    for handle in handles {
        handle.join().expect("worker thread");
    }

    // Identity store path: concurrent enroll + revoke stay consistent.
    let mut handles = Vec::new();
    for thread in 0..8u32 {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            for item in 0..8u32 {
                let vault_hex =
                    format!("{:064x}", u64::from(thread) * 1000 + u64::from(item) + 1);
                let key_hex = format!(
                    "{:064x}",
                    u64::from(thread) * 1_000_000 + u64::from(item) + 0x9e37
                );
                state
                    .enroll_identity(&vault_hex, &key_hex, 0xffff_ffff)
                    .unwrap();
            }
        }));
    }
    for handle in handles {
        handle.join().expect("enroll thread");
    }
    assert_eq!(state.list_enrolled_identities().len(), 64);

    let mut handles = Vec::new();
    for thread in 0..8u32 {
        let state = Arc::clone(&state);
        handles.push(std::thread::spawn(move || {
            for item in 0..8u32 {
                let vault_hex =
                    format!("{:064x}", u64::from(thread) * 1000 + u64::from(item) + 1);
                let key_hex = format!(
                    "{:064x}",
                    u64::from(thread) * 1_000_000 + u64::from(item) + 0x9e37
                );
                assert!(state.revoke_identity(&vault_hex, &key_hex));
            }
        }));
    }
    for handle in handles {
        handle.join().expect("revoke thread");
    }
    assert!(state
        .list_enrolled_identities()
        .iter()
        .all(|identity| identity.revoked_at_utc.is_some()));

    drop(state);
    std::fs::remove_dir_all(root).unwrap();
}
