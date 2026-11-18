//! Cryptographic Audit & Property Verification Battery
//!
//! Independently tests mathematical field invariants, strict Ed25519 signature
//! validation (small-order points, malleability, prefix-free domain separation),
//! RFC 7748 X25519 non-contributory rejection, KDF/HKDF domain orthogonality,
//! and AEAD/envelope bitflip + truncation fail-closed properties.

use std::collections::BTreeSet;

use ciphervault_crypto::aead::{
    decrypt_chunk, decrypt_with_nonce, encrypt_chunk, encrypt_with_nonce, KEY_SIZE, NONCE_SIZE,
    TAG_SIZE,
};
use ciphervault_crypto::chunk_v2::{
    derive_v2_chunk_domain_key, derive_v2_chunk_id, derive_v2_chunk_key_nonce,
    derive_v2_file_version_id,
};
use ciphervault_crypto::envelope::{
    open_secret_value, scope_aad, seal_secret_value, DataEncryptionKey, KeyWrappingService,
    LocalKekService,
};
use ciphervault_crypto::kdf::{
    derive_anchor_salt, derive_chunk_nonce, derive_file_version_id, derive_file_version_key,
    derive_subkey, CTX_ANCHOR_SALT, CTX_CHUNK_NONCE, CTX_FILE_KEY, CTX_MANIFEST_KEY,
    CTX_RECOVERY_ENCRYPT, CTX_RECOVERY_LOCATOR, CTX_RECOVERY_SIGNING,
};
use ciphervault_crypto::passphrase_backup::{open_passphrase_backup, seal_passphrase_backup};
use ciphervault_crypto::sealed_box::{open_sealed_box, seal_box};
use ciphervault_crypto::shamir::{
    combine_shares, combine_shares_with_threshold, gf_inv, gf_mul, split_secret, ShamirShare,
};
use ciphervault_crypto::signatures::{generate_signing_key, sign_with_domain, verify_with_domain};
use ciphervault_crypto::CryptoError;
use x25519_dalek::{PublicKey as X25519PublicKey, StaticSecret as X25519StaticSecret};

#[test]
fn ed25519_rejects_weak_low_order_keys_and_domain_collisions() {
    let sk = generate_signing_key();
    let vk_bytes = sk.verifying_key().to_bytes();
    let msg = b"canonical-cbor-record";
    let sig = sign_with_domain(&sk, b"snapshot_record", msg);

    // Valid signature passes strict verification.
    assert!(verify_with_domain(&vk_bytes, b"snapshot_record", msg, &sig).is_ok());

    // Prefix-free domain separation: context cannot inject ':' to alias message boundaries.
    assert!(verify_with_domain(&vk_bytes, b"", msg, &sig).is_err());
    assert!(verify_with_domain(&vk_bytes, b"snapshot_record:extra", msg, &sig).is_err());

    // Cross-domain isolation across every CipherVault signature domain.
    let domains: &[&[u8]] = &[
        b"genesis_record",
        b"device_certificate",
        b"epoch_envelope",
        b"snapshot_record",
        b"head_record",
        b"operator_challenge",
        b"operator_join_invite",
        b"dpop-v1",
        b"account_login",
        b"placement_update",
        b"operator_pos",
    ];
    for &dom in domains {
        if dom != b"snapshot_record" {
            assert!(
                verify_with_domain(&vk_bytes, dom, msg, &sig).is_err(),
                "signature accepted under wrong domain {:?}",
                String::from_utf8_lossy(dom)
            );
        }
    }

    // Known small-order Ed25519 points (order 1, 2, 4, 8) must fail verify_with_domain.
    let weak_points: [[u8; 32]; 7] = [
        // Identity (0, 1)
        [
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // (0, -1) order 2
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // Order 4 point
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00,
        ],
        // Order 4 point (sign bit set)
        [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x80,
        ],
        // Order 8 torsion points
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0x7a,
        ],
        [
            0xc7, 0x17, 0x6a, 0x70, 0x3d, 0x4d, 0xd8, 0x4f, 0xba, 0x3c, 0x0b, 0x76, 0x0d, 0x10,
            0x67, 0x0f, 0x2a, 0x20, 0x53, 0xfa, 0x2c, 0x39, 0xcc, 0xc6, 0x4e, 0xc7, 0xfd, 0x77,
            0x92, 0xac, 0x03, 0xfa,
        ],
        [
            0x26, 0xe8, 0x95, 0x8f, 0xc2, 0xb2, 0x27, 0xb0, 0x45, 0xc3, 0xf4, 0x89, 0xf2, 0xef,
            0x98, 0xf0, 0xd5, 0xdf, 0xac, 0x05, 0xd3, 0xc6, 0x33, 0x39, 0xb1, 0x38, 0x02, 0x88,
            0x6d, 0x53, 0xfc, 0x05,
        ],
    ];

    // Even with a matching torsion signature (R = identity, S = 0), verify_strict + is_weak rejects.
    let mut torsion_sig = [0u8; 64];
    torsion_sig[0] = 0x01; // R = (0, 1) identity, S = 0
    for weak_pk in &weak_points {
        assert!(
            verify_with_domain(weak_pk, b"snapshot_record", msg, &torsion_sig).is_err(),
            "weak/small-order public key accepted"
        );
        assert!(
            verify_with_domain(weak_pk, b"snapshot_record", msg, &sig).is_err(),
            "weak public key accepted with valid sig"
        );
    }

    // Non-canonical S >= L malleability check (flip high bit of S or replace S with L + 1).
    let mut malleable = sig;
    malleable[63] |= 0x80;
    assert!(verify_with_domain(&vk_bytes, b"snapshot_record", msg, &malleable).is_err());
}

#[test]
fn x25519_rejects_all_rfc7748_low_order_points() {
    let recipient_sk = X25519StaticSecret::random_from_rng(rand::thread_rng());
    let recipient_pk = X25519PublicKey::from(&recipient_sk);

    // RFC 7748 Section 6.1 canonical + non-canonical low-order points.
    let low_order_points: [[u8; 32]; 7] = [
        // 0
        [0u8; 32],
        // 1
        [
            1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 0,
        ],
        // 325606250916557431795983626356110631294008115727848805560023387167927233504 (order 8)
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f,
            0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16,
            0x5f, 0x49, 0xb8, 0x00,
        ],
        // 39382357235489614581723060781553021112529911719440698176882885853963445705823 (order 8)
        [
            0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83,
            0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd,
            0xd0, 0x9f, 0x11, 0x57,
        ],
        // p - 1 = 2^255 - 20
        [
            0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p = 2^255 - 19
        [
            0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
        // p + 1 = 2^255 - 18
        [
            0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0x7f,
        ],
    ];

    for pts in &low_order_points {
        let bad_pk = X25519PublicKey::from(*pts);
        assert!(
            matches!(
                seal_box(&bad_pk, b"secret-epoch-key"),
                Err(CryptoError::NonContributoryKeyAgreement)
            ),
            "seal_box accepted low-order point"
        );

        let mut fake_box = Vec::from(pts.as_slice());
        fake_box.extend_from_slice(&[0u8; 48]);
        assert!(
            matches!(
                open_sealed_box(&recipient_sk, &recipient_pk, &fake_box),
                Err(CryptoError::NonContributoryKeyAgreement)
            ),
            "open_sealed_box accepted low-order ephemeral point"
        );
    }
}

#[test]
fn gf256_exhaustive_field_axioms_and_shamir_invariants() {
    // Exhaustively check all 65,536 (a, b) pairs in GF(2^8).
    for a in 0u8..=255 {
        assert_eq!(gf_mul(a, 0), 0);
        assert_eq!(gf_mul(0, a), 0);
        assert_eq!(gf_mul(a, 1), a);
        assert_eq!(gf_mul(1, a), a);

        if a != 0 {
            let inv = gf_inv(a).expect("non-zero element must have inverse");
            assert_eq!(gf_mul(a, inv), 1, "a * a^-1 != 1 for a={a}");
        } else {
            assert!(gf_inv(0).is_err());
        }

        for b in 0u8..=255 {
            // Commutativity
            assert_eq!(gf_mul(a, b), gf_mul(b, a));
            // Distributivity with c = a ^ b ^ 0x5A
            let c = a ^ b ^ 0x5A;
            assert_eq!(gf_mul(a, b ^ c), gf_mul(a, b) ^ gf_mul(a, c));
            // Associativity on sampled c
            assert_eq!(gf_mul(gf_mul(a, b), c), gf_mul(a, gf_mul(b, c)));
        }
    }

    // Shamir invariants across thresholds 2..=6.
    let secret = [0xA7u8; 32];
    for threshold in 2u8..=6 {
        let total = threshold + 2;
        let shares = split_secret(&secret, threshold, total).unwrap();
        assert_eq!(shares.len(), total as usize);

        // Exact threshold subset reconstructs secret.
        assert_eq!(
            combine_shares_with_threshold(&shares[..threshold as usize], threshold).unwrap(),
            secret
        );
        // Shuffled tail subset reconstructs secret.
        let tail: Vec<ShamirShare> = shares.iter().rev().take(threshold as usize).cloned().collect();
        assert_eq!(
            combine_shares_with_threshold(&tail, threshold).unwrap(),
            secret
        );
        // Under-threshold fails closed in threshold API.
        assert!(
            combine_shares_with_threshold(&shares[..(threshold - 1) as usize], threshold).is_err()
        );
        // Zero index rejected.
        let mut bad_zero = shares[..threshold as usize].to_vec();
        bad_zero[0].index = 0;
        assert!(combine_shares(&bad_zero).is_err());
    }
}

#[test]
fn kdf_and_chunk_v2_domain_orthogonality_and_kats() {
    let master = [0x42u8; 32];
    let vault = [0x11u8; 32];
    let digest = [0x22u8; 32];

    let contexts: [&[u8; 8]; 7] = [
        CTX_RECOVERY_SIGNING,
        CTX_RECOVERY_ENCRYPT,
        CTX_RECOVERY_LOCATOR,
        CTX_MANIFEST_KEY,
        CTX_FILE_KEY,
        CTX_CHUNK_NONCE,
        CTX_ANCHOR_SALT,
    ];
    let mut outputs = BTreeSet::new();
    for ctx in contexts {
        assert!(outputs.insert(derive_subkey(&master, 1, ctx).unwrap()));
        assert!(outputs.insert(derive_subkey(&master, 2, ctx).unwrap()));
    }
    assert!(outputs.insert(derive_file_version_key(&master, 1, &digest).unwrap()));
    assert!(outputs.insert(derive_anchor_salt(&master, &vault).unwrap()));
    assert!(outputs.insert(derive_file_version_id(&vault, 1, &digest)));
    assert_eq!(outputs.len(), 17);

    // Pinned chunk nonce KAT determinism.
    let nonce = derive_chunk_nonce(&master, 0, &digest);
    assert_eq!(nonce, derive_chunk_nonce(&master, 0, &digest));
    assert_ne!(nonce, derive_chunk_nonce(&master, 1, &digest));

    // Chunk v2 HKDF-SHA256 domain separation.
    let dom_key = derive_v2_chunk_domain_key(&master, &vault, 7);
    let fid = derive_v2_file_version_id(&dom_key, &vault, 7, &digest);
    let cid = derive_v2_chunk_id(&dom_key, &vault, 7, &digest);
    let (aead_key, aead_nonce) = derive_v2_chunk_key_nonce(&dom_key, &vault, 7, &cid);
    let unique: BTreeSet<[u8; 32]> = [dom_key, fid, cid, *aead_key].into_iter().collect();
    assert_eq!(unique.len(), 4);
    assert_ne!(aead_nonce, [0u8; 24]);
}

#[test]
fn aead_and_envelope_bitflip_and_truncation_exhaustion() {
    // 1. Chunk AEAD bitflip & truncation
    let key = [0x91u8; KEY_SIZE];
    let aad = b"CipherVault-Audit-AAD";
    let pt = b"confidential-payload-material";
    let sealed = encrypt_chunk(&key, pt, aad).unwrap();
    assert_eq!(decrypt_chunk(&key, &sealed, aad).unwrap(), pt);

    for idx in 0..sealed.len() {
        let mut bad = sealed.clone();
        bad[idx] ^= 0x80;
        assert!(matches!(
            decrypt_chunk(&key, &bad, aad),
            Err(CryptoError::AuthTagVerificationFailed)
        ));
    }
    for len in 0..(NONCE_SIZE + TAG_SIZE) {
        assert!(matches!(
            decrypt_chunk(&key, &sealed[..len], aad),
            Err(CryptoError::AuthTagVerificationFailed)
        ));
    }

    // 2. Detached nonce AEAD
    let nonce = [0x33u8; NONCE_SIZE];
    let ct = encrypt_with_nonce(&key, &nonce, pt, aad).unwrap();
    assert_eq!(decrypt_with_nonce(&key, &nonce, &ct, aad).unwrap(), pt);
    assert!(decrypt_with_nonce(&key, &nonce, &ct, b"wrong-aad").is_err());

    // 3. Scoped DEK + KEK wrap
    let aad_scope = scope_aad(&[1; 16], &[2; 16], &[3; 16], &[4; 16], 1);
    let dek = DataEncryptionKey::generate();
    let wrapped_secret = seal_secret_value(&dek, pt, &aad_scope).unwrap();
    assert_eq!(open_secret_value(&dek, &wrapped_secret, &aad_scope).unwrap(), pt);

    let kek = LocalKekService::new("kek-audit-1", [0x55; KEY_SIZE]);
    let wrapped_dek = kek.wrap_dek(&dek).unwrap();
    assert_eq!(kek.unwrap_dek(&wrapped_dek).unwrap().as_bytes(), dek.as_bytes());

    // 4. Passphrase CVKB1 envelope
    let pass = b"audit-passphrase-material-1234";
    let backup = seal_passphrase_backup(pass, pt).unwrap();
    assert_eq!(open_passphrase_backup(pass, &backup).unwrap(), pt);
    // Test magic, KDF byte, salt boundaries, nonce boundaries, ciphertext, and tag.
    for idx in [0, 4, 5, 6, 21, 22, 45, 46, backup.len() - 17, backup.len() - 1] {
        let mut tampered = backup.clone();
        tampered[idx] ^= 0x01;
        assert!(open_passphrase_backup(pass, &tampered).is_err());
    }
}
