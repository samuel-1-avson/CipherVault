use ciphervault_crypto::hsm::{HardwareSecurityModule, HsmDevice, HsmSlot, SoftwareHsmSimulator};
use ciphervault_crypto::piv::{
    list_pcsc_readers, CommandApdu, PcscHardwareToken, ResponseApdu, ALG_ED25519, ALG_X25519,
    PIV_AID, PIV_SLOT_KEY_MANAGEMENT, PIV_SLOT_SIGNATURE,
};
use ciphervault_crypto::signatures::verify_with_domain;

#[test]
fn test_piv_apdu_command_construction() {
    // 1. SELECT PIV Application APDU
    let select = CommandApdu::select_piv();
    let select_bytes = select.to_bytes();
    assert_eq!(select_bytes[0], 0x00); // CLA
    assert_eq!(select_bytes[1], 0xA4); // INS (SELECT)
    assert_eq!(select_bytes[2], 0x04); // P1 (Select by name)
    assert_eq!(select_bytes[3], 0x00); // P2
    assert_eq!(select_bytes[4], 11); // Lc length
    assert_eq!(&select_bytes[5..16], &PIV_AID);
    assert_eq!(select_bytes[16], 0x00); // Le

    // 2. VERIFY PIN APDU
    let verify = CommandApdu::verify_pin(b"654321");
    let verify_bytes = verify.to_bytes();
    assert_eq!(verify_bytes[0], 0x00);
    assert_eq!(verify_bytes[1], 0x20); // INS (VERIFY)
    assert_eq!(verify_bytes[2], 0x00);
    assert_eq!(verify_bytes[3], 0x80); // P2 (PIN reference)
    assert_eq!(verify_bytes[4], 8); // 8-byte padded PIN
    assert_eq!(&verify_bytes[5..11], b"654321");
    assert_eq!(verify_bytes[11], 0xFF);
    assert_eq!(verify_bytes[12], 0xFF);

    // 3. GET METADATA APDU
    let meta = CommandApdu::get_slot_metadata(PIV_SLOT_SIGNATURE);
    let meta_bytes = meta.to_bytes();
    assert_eq!(meta_bytes[0], 0x00);
    assert_eq!(meta_bytes[1], 0xF7); // INS (YubiKey GET METADATA)
    assert_eq!(meta_bytes[3], 0x9C); // Slot 9C

    // 4. GENERAL AUTHENTICATE APDU (Sign)
    let challenge = [0xAAu8; 32];
    let sign_apdu =
        CommandApdu::general_authenticate_sign(ALG_ED25519, PIV_SLOT_SIGNATURE, &challenge);
    let sign_bytes = sign_apdu.to_bytes();
    assert_eq!(sign_bytes[1], 0x87); // GENERAL AUTHENTICATE
    assert_eq!(sign_bytes[2], ALG_ED25519);
    assert_eq!(sign_bytes[3], PIV_SLOT_SIGNATURE);
    assert_eq!(sign_bytes[5], 0x7C); // Tag 7C template

    // 5. GENERAL AUTHENTICATE APDU (ECDH)
    let peer_pk = [0xBBu8; 32];
    let ecdh_apdu =
        CommandApdu::general_authenticate_ecdh(ALG_X25519, PIV_SLOT_KEY_MANAGEMENT, &peer_pk);
    let ecdh_bytes = ecdh_apdu.to_bytes();
    assert_eq!(ecdh_bytes[1], 0x87);
    assert_eq!(ecdh_bytes[2], ALG_X25519);
    assert_eq!(ecdh_bytes[3], PIV_SLOT_KEY_MANAGEMENT);
    assert_eq!(ecdh_bytes[5], 0x7C);
}

#[test]
fn test_piv_response_apdu_and_status_codes() {
    // Standard Success
    let resp = ResponseApdu::parse(&[0x01, 0x02, 0x90, 0x00]).unwrap();
    assert!(resp.is_success());
    assert_eq!(resp.data, vec![0x01, 0x02]);

    // Touch Timeout / User Presence Cancelled (69 85)
    let resp_timeout = ResponseApdu::parse(&[0x69, 0x85]).unwrap();
    assert!(!resp_timeout.is_success());
    assert!(resp_timeout.is_touch_timeout());
    assert!(resp_timeout.error_description().contains("presence"));

    // PIN Required / Security Status Not Satisfied (69 82)
    let resp_pin = ResponseApdu::parse(&[0x69, 0x82]).unwrap();
    assert!(resp_pin.is_pin_required());
    assert!(resp_pin.error_description().contains("PIN"));

    // Dynamic Auth Template Extraction (Tag 7C -> Tag 82 Signature)
    let sample_sig = vec![0x33u8; 64];
    let mut template_payload = vec![0x7C, 66, 0x82, 64];
    template_payload.extend_from_slice(&sample_sig);
    template_payload.push(0x90);
    template_payload.push(0x00);

    let auth_resp = ResponseApdu::parse(&template_payload).unwrap();
    assert!(auth_resp.is_success());
    let extracted = auth_resp.extract_dynamic_auth_response(0x82).unwrap();
    assert_eq!(extracted, sample_sig);
}

#[test]
fn test_pcsc_subsystem_safety_and_probe() {
    // Verify that enumerating PC/SC smartcard readers does not panic or fail
    let readers = list_pcsc_readers().expect("list_pcsc_readers must be safe");
    println!("Detected PC/SC smartcard readers count: {}", readers.len());
    for r in &readers {
        println!("  - {}", r);
    }

    // Probing for hardware token:
    // If no physical token is attached in CI, it gracefully returns Ok(None)
    let probe_res = PcscHardwareToken::probe();
    assert!(
        probe_res.is_ok(),
        "Hardware token probe must not return hard system error"
    );

    match probe_res.unwrap() {
        Some(token) => {
            println!("Physical hardware token attached: {}", token.reader_name());
            assert!(token.is_connected());
        }
        None => {
            println!("No physical smartcard attached; graceful detection validated.");
        }
    }
}

#[test]
fn test_unified_hsm_device_abstraction() {
    // 1. Probe or fall back to virtual software simulator
    let device = HsmDevice::probe_or_virtual();
    assert!(device.is_connected());

    // 2. Query Slot 9C (Digital Signature)
    let pk_9c = device
        .get_public_key(HsmSlot::DigitalSignature)
        .expect("Must read Slot 9C public key");
    assert_eq!(pk_9c.len(), 32);

    let info_9c = device
        .get_slot_info(HsmSlot::DigitalSignature)
        .expect("Must read Slot 9C metadata");
    assert_eq!(info_9c.slot, HsmSlot::DigitalSignature);
    assert!(!info_9c.algorithm.is_empty());
    assert!(!info_9c.touch_policy.is_empty());

    // 3. Delegate digital signature to Slot 9C
    let domain = b"CIPHERVAULT-TEST-TOKEN";
    let test_digest = [0x77u8; 32];
    let signature = device
        .sign_digest(HsmSlot::DigitalSignature, domain, &test_digest)
        .expect("Signature delegation must succeed");
    assert_eq!(signature.len(), 64);

    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_9c);

    // Cryptographically verify signature using public key
    assert!(verify_with_domain(&pk_arr, domain, &test_digest, &signature).is_ok());

    // Mismatched digest is rejected
    let bad_digest = [0x88u8; 32];
    assert!(verify_with_domain(&pk_arr, domain, &bad_digest, &signature).is_err());

    // 4. Query Slot 9D (Key Management / ECDH)
    let pk_9d = device
        .get_public_key(HsmSlot::KeyManagement)
        .expect("Must read Slot 9D public key");
    assert_eq!(pk_9d.len(), 32);

    // Create a second device to test ECDH agreement
    let peer_device = SoftwareHsmSimulator::generate();
    let peer_pk = peer_device
        .get_public_key(HsmSlot::KeyManagement)
        .expect("Must read peer Slot 9D public key");

    let mut peer_pk_arr = [0u8; 32];
    peer_pk_arr.copy_from_slice(&peer_pk);

    let shared_secret_a = device
        .ecdh_key_agreement(HsmSlot::KeyManagement, &peer_pk_arr)
        .expect("ECDH agreement A -> B must succeed");

    let mut pk_9d_arr = [0u8; 32];
    pk_9d_arr.copy_from_slice(&pk_9d);

    let shared_secret_b = peer_device
        .ecdh_key_agreement(HsmSlot::KeyManagement, &pk_9d_arr)
        .expect("ECDH agreement B -> A must succeed");

    assert_eq!(
        shared_secret_a, shared_secret_b,
        "ECDH shared secrets between hardware tokens must match"
    );
    assert_ne!(shared_secret_a, [0u8; 32]);
}

#[test]
fn test_hardware_token_snapshot_and_head_signing_ceremony() {
    use ciphervault_crypto::VaultEpochKey;
    use ciphervault_format::{HeadRecord, PROTOCOL_VERSION};
    use ciphervault_snapshot::{create_snapshot_with_signer, DeviceSigner};
    use std::fs;

    // 1. Initialize hardware token simulator
    let hsm = SoftwareHsmSimulator::generate();
    let pk_9c = hsm
        .get_public_key(HsmSlot::DigitalSignature)
        .expect("Must retrieve Slot 9C public key");
    assert_eq!(pk_9c.len(), 32);
    let mut pk_arr = [0u8; 32];
    pk_arr.copy_from_slice(&pk_9c);

    // 2. Prepare test directory and file for snapshot creation
    let temp_dir = std::env::temp_dir().join(format!(
        "ciphervault_hw_test_{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_millis()
    ));
    fs::create_dir_all(&temp_dir).unwrap();
    let test_file = temp_dir.join("secret_document.txt");
    fs::write(&test_file, b"Hardware-authenticated confidential content").unwrap();

    let tracked_files = vec![(
        std::path::PathBuf::from("secret_document.txt"),
        [0x11u8; 32],
    )];
    let vault_id = [0x55u8; 32];
    let epoch = 1u64;
    let epoch_key = VaultEpochKey::from_bytes([0x99u8; 32]);
    let device_id = [0x22u8; 32];

    // 3. Create snapshot using hardware token signing authority
    let signer = DeviceSigner::Hardware(&hsm, HsmSlot::DigitalSignature);
    let snapshot_output = create_snapshot_with_signer(
        &temp_dir,
        &tracked_files,
        &vault_id,
        epoch,
        &epoch_key,
        vec![],
        &device_id,
        1,
        1,
        &signer,
    )
    .expect("Snapshot creation with hardware signer must succeed");

    // 4. Verify SnapshotRecord hardware signature against Slot 9C public key
    assert_eq!(snapshot_output.record.signature.len(), 64);
    assert!(
        snapshot_output.record.verify(&pk_arr).is_ok(),
        "Hardware-signed snapshot record must verify against device public key"
    );

    // Tampering test on SnapshotRecord
    let mut tampered_record = snapshot_output.record.clone();
    tampered_record.device_counter += 1;
    assert!(
        tampered_record.verify(&pk_arr).is_err(),
        "Tampered snapshot record must fail verification"
    );

    // 5. Create HeadRecord and sign via HSM ceremony
    let snapshot_id = snapshot_output.record.snapshot_id.clone();
    let closure_digest = snapshot_output
        .closure
        .compute_base_closure_digest()
        .unwrap();
    let mut head = HeadRecord {
        version: PROTOCOL_VERSION,
        vault_id: vault_id.to_vec(),
        snapshot_id,
        parent_snapshot_ids: Vec::new(),
        closure_digest: closure_digest.to_vec(),
        device_id: device_id.to_vec(),
        device_counter: 1,
        signature: Vec::new(),
    };

    head.sign_with_hsm(&hsm, HsmSlot::DigitalSignature)
        .expect("HeadRecord signing with HSM must succeed");
    assert_eq!(head.signature.len(), 64);

    // 6. Verify HeadRecord hardware signature against Slot 9C public key
    assert!(
        head.verify(&pk_arr).is_ok(),
        "Hardware-signed head record must verify against device public key"
    );

    // Tampering test on HeadRecord
    let mut tampered_head = head.clone();
    tampered_head.device_counter += 1;
    assert!(
        tampered_head.verify(&pk_arr).is_err(),
        "Tampered head record must fail verification"
    );

    // Clean up
    let _ = fs::remove_dir_all(&temp_dir);
}
