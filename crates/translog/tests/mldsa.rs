//! ML-DSA-44 cosignatures: cross-implementation vectors from the Go
//! implementations, plus round-trip and tamper tests. Sources and licenses
//! are listed in `tests/vectors/README.md`.

use base64::engine::general_purpose::STANDARD;
use base64::Engine as _;
use ciphervault_translog::checkpoint::{open_checkpoint, Checkpoint, CheckpointError};
use ciphervault_translog::cosignature::{cosignature_timestamp, WitnessVerifier};
use ciphervault_translog::mldsa::{
    cosigned_subtree, MlDsa44CosignatureSigner, MlDsa44CosignatureVerifier,
    MLDSA44_COSIGNATURE_LEN, MLDSA44_PUBLIC_KEY_LEN, SIG_TYPE_MLDSA44,
};
use ciphervault_translog::note::{
    Ed25519NoteSigner, KeyError, Note, NoteError, NoteSignature, NoteVerifier, VerifierKey,
};
use ciphervault_translog::{leaf_hash, root_from_leaf_hashes, Hash};
use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

const TORCHWOOD: &str = include_str!("vectors/torchwood-litewitness-mldsa.txt");
const TORCHWOOD_SHA256: &str = "f8839e252ee45668911ab92152bf97140a909aeae4bc3399329d84c217b5f8f0";

const FORMATS: &str = include_str!("vectors/transparency-dev-formats-mldsa.txt");
const FORMATS_SHA256: &str = "487b3793a4b307c501372b9cef9c6272fa247891fc8d5e59212db95f94c8485b";

fn normalized(text: &str) -> String {
    text.replace("\r\n", "\n")
}

/// The torchwood vector: the log's ML-DSA-44 verifier key, then its signed
/// checkpoint.
fn torchwood() -> (String, String) {
    let text = normalized(TORCHWOOD);
    let (vkey, note) = text.split_once("\n\n").expect("vkey, blank line, note");
    (vkey.to_owned(), note.to_owned())
}

/// One `-- name --` section of the transparency-dev/formats vector file.
fn formats(section: &str) -> String {
    let text = normalized(FORMATS);
    let header = format!("-- {section} --\n");
    let start = text.find(&header).expect("section exists") + header.len();
    let end = text[start..]
        .find("\n-- ")
        .map_or(text.len(), |i| start + i + 1);
    text[start..end].to_owned()
}

fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

fn checkpoint(origin: &str, size: u64) -> Checkpoint {
    let leaves: Vec<Hash> = (0..size).map(|i| leaf_hash(&i.to_be_bytes())).collect();
    Checkpoint::new(origin, size, root_from_leaf_hashes(&leaves)).unwrap()
}

// ---------------------------------------------------------------------------
// FiloSottile/torchwood cmd/litewitness/testdata/mldsa.txt
// ---------------------------------------------------------------------------

#[test]
fn torchwood_vector_is_intact() {
    assert_eq!(sha256_hex(&normalized(TORCHWOOD)), TORCHWOOD_SHA256);
}

#[test]
fn torchwood_log_checkpoint_verifies() {
    let (vkey, note) = torchwood();
    let verifier = MlDsa44CosignatureVerifier::from_vkey(&vkey).unwrap();
    assert_eq!(verifier.name(), "example.com/mldsa-log");
    assert_eq!(verifier.key_id(), 0xb5df45c5);
    assert_eq!(verifier.public_key().len(), MLDSA44_PUBLIC_KEY_LEN);
    assert_eq!(verifier.verifier_key().unwrap().to_string(), vkey);

    let parsed = Note::parse(note.as_bytes()).unwrap();
    let verified = parsed.verify(&[&verifier as &dyn NoteVerifier]).unwrap();
    assert_eq!(verified.verified().len(), 1);
    let signature = &verified.verified()[0];
    assert_eq!(signature.signature().len(), MLDSA44_COSIGNATURE_LEN);
    assert_eq!(cosignature_timestamp(signature), Some(0));

    let checkpoint = Checkpoint::parse_text(verified.text()).unwrap();
    assert_eq!(checkpoint.origin(), "example.com/mldsa-log");
    assert_eq!(checkpoint.size(), 1);
    assert_eq!(
        verifier.verify_cosignature(&checkpoint, signature.signature()),
        Some(0)
    );

    // The same key through the generic witness type.
    let witness = WitnessVerifier::from_vkey(&vkey).unwrap();
    assert_eq!(witness.sig_type(), SIG_TYPE_MLDSA44);
    assert_eq!(
        witness.verify_cosignature(&checkpoint, signature.signature()),
        Some(0)
    );
}

#[test]
fn torchwood_checkpoint_tampering_is_rejected() {
    let (vkey, note) = torchwood();
    let verifier = MlDsa44CosignatureVerifier::from_vkey(&vkey).unwrap();
    let parsed = Note::parse(note.as_bytes()).unwrap();
    let signature = parsed.signatures()[0].signature().to_vec();
    let checkpoint = Checkpoint::parse_text(parsed.text()).unwrap();

    // A different size, root or origin.
    let other_size = Checkpoint::new(checkpoint.origin(), 2, *checkpoint.root()).unwrap();
    assert_eq!(verifier.verify_cosignature(&other_size, &signature), None);
    let mut root = *checkpoint.root();
    root[31] ^= 1;
    let other_root = Checkpoint::new(checkpoint.origin(), 1, root).unwrap();
    assert_eq!(verifier.verify_cosignature(&other_root, &signature), None);
    let other_origin = Checkpoint::new("example.com/other", 1, *checkpoint.root()).unwrap();
    assert_eq!(verifier.verify_cosignature(&other_origin, &signature), None);

    // A different timestamp, and every 97th signature byte flipped.
    let mut later = signature.clone();
    later[7] = 1;
    assert_eq!(verifier.verify_cosignature(&checkpoint, &later), None);
    for i in (8..signature.len()).step_by(97) {
        let mut bad = signature.clone();
        bad[i] ^= 0x10;
        assert_eq!(
            verifier.verify_cosignature(&checkpoint, &bad),
            None,
            "byte {i}"
        );
    }
    assert_eq!(
        verifier.verify_cosignature(&checkpoint, &signature[..signature.len() - 1]),
        None
    );

    // The message commits to the cosigner name: the same key under another
    // name does not verify.
    let renamed =
        MlDsa44CosignatureVerifier::new("example.com/witness", verifier.public_key()).unwrap();
    assert_eq!(renamed.verify_cosignature(&checkpoint, &signature), None);

    // Extension lines are not covered, so they are refused.
    let extended = checkpoint
        .clone()
        .with_extensions(vec!["extra".into()])
        .unwrap();
    assert_eq!(verifier.verify_cosignature(&extended, &signature), None);

    // A note-level signature from the known key that fails rejects the note.
    let tampered = note.replacen("\n1\n", "\n2\n", 1);
    assert!(matches!(
        Note::parse(tampered.as_bytes())
            .unwrap()
            .verify(&[&verifier as &dyn NoteVerifier]),
        Err(NoteError::InvalidSignature { .. })
    ));
}

// ---------------------------------------------------------------------------
// transparency-dev/formats note/note_cosigv1_test.go
// ---------------------------------------------------------------------------

#[test]
fn formats_vector_is_intact() {
    assert_eq!(sha256_hex(&normalized(FORMATS)), FORMATS_SHA256);
}

#[test]
fn formats_vkey_key_id() {
    let vkey = formats("vkey-key-id");
    let vkey = vkey.trim_end();
    let parsed = VerifierKey::parse(vkey).unwrap();
    assert_eq!(parsed.sig_type(), SIG_TYPE_MLDSA44);
    assert_eq!(parsed.key_id(), 0x31236897);
    let verifier = MlDsa44CosignatureVerifier::from_verifier_key(&parsed).unwrap();
    assert_eq!(verifier.key_id(), 0x31236897);
    assert_eq!(parsed.to_string(), vkey);
}

#[test]
fn formats_private_key_seed_derives_its_key_id() {
    // "PRIVATE+KEY+<name>+<key ID>+base64(0x06 || 32-byte seed)". The key
    // ID is computed from the public key, so deriving the key from the seed
    // must reproduce it: a check of FIPS 204 key generation against Go.
    let skey = formats("private-key");
    let parts: Vec<&str> = skey.trim_end().split('+').collect();
    assert_eq!(&parts[..2], &["PRIVATE", "KEY"]);
    let (name, id_hex, encoded) = (parts[2], parts[3], parts[4]);
    let raw = STANDARD.decode(encoded).unwrap();
    assert_eq!(raw[0], SIG_TYPE_MLDSA44);
    let seed: [u8; 32] = raw[1..].try_into().unwrap();

    let signer = MlDsa44CosignatureSigner::from_seed(name, &seed).unwrap();
    assert_eq!(format!("{:08x}", signer.key_id()), id_hex);
    assert_eq!(signer.public_key().len(), MLDSA44_PUBLIC_KEY_LEN);
}

#[test]
fn formats_witness_cosignature_verifies() {
    let witness = WitnessVerifier::from_vkey(formats("witness-vkey").trim_end()).unwrap();
    assert_eq!(witness.name(), "witness.example/w1");
    assert_eq!(witness.key_id(), 0xa0d0cd91);

    let note = Note::parse(formats("checkpoint").as_bytes()).unwrap();
    let verified = note.verify(&[&witness as &dyn NoteVerifier]).unwrap();
    let checkpoint = Checkpoint::parse_text(verified.text()).unwrap();
    assert_eq!(checkpoint.origin(), "example.com/log");
    assert_eq!(checkpoint.size(), 15);
    // 2009-11-10 23:00:00 UTC, the Go playground's clock.
    assert_eq!(
        cosignature_timestamp(&verified.verified()[0]),
        Some(1_257_894_000)
    );
    assert_eq!(
        witness.verify_cosignature(&checkpoint, verified.verified()[0].signature()),
        Some(1_257_894_000)
    );
}

#[test]
fn formats_subtree_cosignature_verifies() {
    let verifier =
        MlDsa44CosignatureVerifier::from_vkey(formats("witness-vkey").trim_end()).unwrap();
    let line = formats("subtree-signature");
    let signature = NoteSignature::parse_line(line.trim_end()).unwrap();
    assert_eq!(signature.key_id(), verifier.key_id());
    // The vector carries a zero timestamp before the bare signature.
    let (timestamp, bare) = signature.signature().split_at(8);
    assert_eq!(timestamp, &[0; 8]);

    let hash: Hash = Sha256::digest(b"test").into();
    assert!(verifier.verify_subtree("example.com/log", 8, 16, &hash, bare));
    assert!(!verifier.verify_subtree("example.com/log", 8, 15, &hash, bare));
    assert!(!verifier.verify_subtree("example.com/log", 0, 16, &hash, bare));
    assert!(!verifier.verify_subtree("example.com/other", 8, 16, &hash, bare));
}

// ---------------------------------------------------------------------------
// Round trips with deterministic keys
// ---------------------------------------------------------------------------

#[test]
fn cosign_round_trip() {
    let signer = MlDsa44CosignatureSigner::from_seed("witness.example/w2", &[7; 32]).unwrap();
    let verifier = signer.verifier().unwrap();
    // Key ID is SHA-256(name || 0x0A || 0x06 || public key)[:4].
    let mut id_input = b"witness.example/w2\n\x06".to_vec();
    id_input.extend_from_slice(signer.public_key());
    let digest = Sha256::digest(&id_input);
    assert_eq!(
        signer.key_id(),
        u32::from_be_bytes([digest[0], digest[1], digest[2], digest[3]])
    );
    assert_eq!(verifier.key_id(), signer.key_id());

    let checkpoint = checkpoint("example.com/log", 9);
    let cosignature = signer.cosign(&checkpoint, 1_700_000_000).unwrap();
    assert_eq!(cosignature.name(), "witness.example/w2");
    assert_eq!(cosignature.signature().len(), MLDSA44_COSIGNATURE_LEN);
    assert_eq!(
        verifier.verify_cosignature(&checkpoint, cosignature.signature()),
        Some(1_700_000_000)
    );
    // Deterministic signing: same input, same bytes.
    assert_eq!(
        signer.cosign(&checkpoint, 1_700_000_000).unwrap(),
        cosignature
    );
    assert_ne!(
        signer.cosign(&checkpoint, 1_700_000_001).unwrap(),
        cosignature
    );

    // The vkey round-trips and selects the ML-DSA verifier.
    let vkey = signer.verifier_key().unwrap().to_string();
    assert_eq!(
        WitnessVerifier::from_vkey(&vkey).unwrap(),
        WitnessVerifier::MlDsa44(verifier)
    );

    // Subtree cosignatures too.
    let hash = [9; 32];
    let bare = signer.sign_subtree("example.com/log", 4, 8, &hash).unwrap();
    assert!(signer
        .verifier()
        .unwrap()
        .verify_subtree("example.com/log", 4, 8, &hash, &bare));
}

#[test]
fn open_checkpoint_with_mldsa_and_ed25519_witnesses() {
    let log = Ed25519NoteSigner::new("example.com/log", SigningKey::from_bytes(&[1; 32])).unwrap();
    let mldsa = MlDsa44CosignatureSigner::from_seed("witness.example/pq", &[2; 32]).unwrap();
    let ed = ciphervault_translog::CosignatureV1Signer::new(
        "witness.example/ed",
        SigningKey::from_bytes(&[3; 32]),
    )
    .unwrap();

    let checkpoint = checkpoint("example.com/log", 5);
    let mut note = checkpoint.sign(&log).unwrap();
    note.add_signature(mldsa.cosign(&checkpoint, 100).unwrap())
        .unwrap();
    note.add_signature(ed.cosign(&checkpoint, 200).unwrap())
        .unwrap();
    let signed = note.encode().unwrap();

    let witnesses = [
        WitnessVerifier::from(mldsa.verifier().unwrap()),
        WitnessVerifier::from(ed.verifier().unwrap()),
    ];
    let opened = open_checkpoint(
        signed.as_bytes(),
        "example.com/log",
        &log.verifier().unwrap(),
        &witnesses,
    )
    .unwrap();
    let got: Vec<(&str, u64)> = opened
        .cosignatures()
        .iter()
        .map(|c| (c.name(), c.timestamp()))
        .collect();
    assert_eq!(
        got,
        vec![("witness.example/pq", 100), ("witness.example/ed", 200)]
    );

    // A known witness's cosignature with a swapped timestamp (the signature
    // for 101 relabelled as 100) rejects the whole note.
    let later = mldsa.cosign(&checkpoint, 101).unwrap();
    let mut raw = 100u64.to_be_bytes().to_vec();
    raw.extend_from_slice(&later.signature()[8..]);
    let mut forged = checkpoint.sign(&log).unwrap();
    forged
        .add_signature(NoteSignature::new(mldsa.name(), mldsa.key_id(), raw).unwrap())
        .unwrap();
    assert!(matches!(
        open_checkpoint(
            forged.encode().unwrap().as_bytes(),
            "example.com/log",
            &log.verifier().unwrap(),
            &witnesses
        ),
        Err(CheckpointError::Note(NoteError::InvalidSignature { .. }))
    ));
}

#[test]
fn mldsa_cosignatures_refuse_extension_lines() {
    let log = Ed25519NoteSigner::new("example.com/log", SigningKey::from_bytes(&[1; 32])).unwrap();
    let mldsa = MlDsa44CosignatureSigner::from_seed("witness.example/pq", &[2; 32]).unwrap();
    let plain = checkpoint("example.com/log", 3);
    let extended = plain.clone().with_extensions(vec!["note".into()]).unwrap();

    assert_eq!(
        mldsa.cosign(&extended, 1),
        Err(NoteError::UncoveredExtensions)
    );

    // A cosignature over the plain checkpoint, attached to the extended
    // one, must not make the extension lines look witnessed.
    let mut note = extended.sign(&log).unwrap();
    note.add_signature(mldsa.cosign(&plain, 1).unwrap())
        .unwrap();
    let err = open_checkpoint(
        note.encode().unwrap().as_bytes(),
        "example.com/log",
        &log.verifier().unwrap(),
        &[mldsa.verifier().unwrap().into()],
    )
    .unwrap_err();
    assert!(matches!(
        err,
        CheckpointError::Note(NoteError::InvalidSignature { .. })
    ));
}

#[test]
fn key_and_input_validation() {
    let signer = MlDsa44CosignatureSigner::from_seed("w", &[0; 32]).unwrap();
    assert_eq!(
        MlDsa44CosignatureSigner::from_seed("a b", &[0; 32]).unwrap_err(),
        KeyError::InvalidName
    );
    assert_eq!(
        MlDsa44CosignatureVerifier::new("w", &signer.public_key()[1..]).unwrap_err(),
        KeyError::InvalidPublicKey
    );
    assert_eq!(
        MlDsa44CosignatureVerifier::new("w".repeat(256), signer.public_key()).unwrap_err(),
        KeyError::InvalidName
    );

    // Type dispatch: an Ed25519 note key is neither witness type.
    let ed_note = Ed25519NoteSigner::new("log", SigningKey::from_bytes(&[5; 32]))
        .unwrap()
        .verifier()
        .unwrap()
        .verifier_key()
        .to_string();
    assert_eq!(
        WitnessVerifier::from_vkey(&ed_note).unwrap_err(),
        KeyError::UnsupportedType(0x01)
    );
    assert_eq!(
        MlDsa44CosignatureVerifier::from_vkey(&ed_note).unwrap_err(),
        KeyError::UnsupportedType(0x01)
    );

    // Timestamps above 2^63 - 1 are refused.
    assert_eq!(
        signer.cosign(&checkpoint("log", 1), 1 << 63),
        Err(NoteError::TimestampOutOfRange)
    );
    assert!(cosigned_subtree("w", 1 << 63, "log", 0, 1, &[0; 32]).is_none());
}
